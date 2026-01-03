# app.py
# FastAPI webhook receiver for Alchemy (EVM) + Telegram alerts
# - Verifies X-Alchemy-Signature (HMAC-SHA256 of raw body)
# - Tracks only WATCH_WALLETS_EVM (EOAs recommended; routers/contracts will be noisy)
# - Ignores TRANSFER spam by default (only BUY/SELL/SWAP)
# - Adds infra blocklist safety net (Uniswap/1inch/Permit2 etc.)
# - Optional minimum-size filters
# - Optional Dexscreener enrichment (price/liquidity/volume + link)

import os
import json
import time
import hmac
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict, deque

import requests
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse

# -----------------------------
# Logging
# -----------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)
log = logging.getLogger("wallet-webhook")

# -----------------------------
# ENV helpers
# -----------------------------
def getenv_required(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

def parse_csv_set(name: str) -> set[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return set()
    return set(x for x in raw.replace(" ", "").split(",") if x)

def clamp_str(s: str, n: int = 3500) -> str:
    return s if len(s) <= n else (s[: n - 20] + "\n…(truncated)…")

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = getenv_required("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = int(getenv_required("TELEGRAM_CHAT_ID"))

TG_MIN_INTERVAL = float(os.getenv("TG_MIN_INTERVAL", "1.0"))  # seconds between messages
_last_tg_ts = 0.0

tg_session = requests.Session()
TG_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

def tg_send(text: str, silent: bool = False) -> None:
    global _last_tg_ts
    now = time.time()
    wait = TG_MIN_INTERVAL - (now - _last_tg_ts)
    if wait > 0:
        time.sleep(wait)

    r = tg_session.post(
        f"{TG_BASE}/sendMessage",
        json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": clamp_str(text),
            "disable_notification": bool(silent),
            "disable_web_page_preview": True,
        },
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data)
    _last_tg_ts = time.time()

# -----------------------------
# Security (Alchemy Signature)
# -----------------------------
ALCHEMY_SIGNING_KEY = os.getenv("ALCHEMY_SIGNING_KEY", "").encode()

def verify_alchemy_signature(raw_body: bytes, sig_header: Optional[str]) -> None:
    """
    Alchemy sends X-Alchemy-Signature.
    Verify HMAC-SHA256(raw_body, ALCHEMY_SIGNING_KEY) equals the signature hex.
    If ALCHEMY_SIGNING_KEY is not set, we do not block (useful for testing).
    """
    if not ALCHEMY_SIGNING_KEY:
        return

    if not sig_header:
        raise HTTPException(status_code=401, detail="Missing X-Alchemy-Signature")

    sig = sig_header.strip()
    # tolerate possible prefix formats
    if sig.startswith("sha256="):
        sig = sig.split("=", 1)[1].strip()

    expected = hmac.new(ALCHEMY_SIGNING_KEY, raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.lower(), expected.lower()):
        raise HTTPException(status_code=401, detail="Invalid X-Alchemy-Signature")

# Optional shared secret (if you want it)
EVM_WEBHOOK_SECRET = os.getenv("EVM_WEBHOOK_SECRET", "").strip()

def check_secret(auth_header: Optional[str], expected: str) -> None:
    if not expected:
        return
    if not auth_header or auth_header.strip() != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")

# -----------------------------
# Watchlist (EOAs recommended)
# -----------------------------
WATCH_WALLETS_EVM = {w.lower() for w in parse_csv_set("WATCH_WALLETS_EVM")}

def is_tracked(wallet: str) -> bool:
    """
    If you forgot to set WATCH_WALLETS_EVM, don't block everything
    (your requested behavior).
    """
    if not WATCH_WALLETS_EVM:
        return True
    return (wallet or "").lower() in WATCH_WALLETS_EVM

# -----------------------------
# Filters / behavior
# -----------------------------
# Ignore plain transfers (spam) – keep only trade-like activity
IGNORE_TRANSFERS = os.getenv("IGNORE_TRANSFERS", "1").strip() not in ("0", "false", "False")

# Minimum-size filters (optional)
MIN_QUOTE_USD = float(os.getenv("MIN_QUOTE_USD", "0"))   # if you later add USD pricing; kept for future
MIN_NATIVE = float(os.getenv("MIN_NATIVE", "0"))         # e.g. 0.1 to ignore tiny ETH transfers (only affects TRANSFER if not ignored)

QUOTE_SYMBOLS = {s.strip().upper() for s in os.getenv("QUOTE_SYMBOLS_EVM", "ETH,WETH,USDC,USDT,DAI").split(",") if s.strip()}

# Infra blocklist safety net (lowercase 0x…)
INFRA_BLOCKLIST = {x.lower() for x in parse_csv_set("INFRA_BLOCKLIST")}
# Provide sane defaults if user doesn't set it:
if not INFRA_BLOCKLIST:
    INFRA_BLOCKLIST = {
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap SwapRouter02
        "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",  # Uniswap UniversalRouter
        "0x000000000022d473030f116ddee9f6b43ac78ba3",  # Permit2
        "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch Router v5
        "0x9008d19f58aabd9ed0d60971565aa8510560ab41",  # CoW settlement (not a trader wallet)
    }

# -----------------------------
# Dedupe
# -----------------------------
DEDUP_MAX = int(os.getenv("DEDUP_MAX", "50000"))
_dedupe = set()
_dedupe_q = deque(maxlen=DEDUP_MAX)

def remember_once(key: str) -> bool:
    if key in _dedupe:
        return False
    _dedupe.add(key)
    _dedupe_q.append(key)
    while len(_dedupe) > _dedupe_q.maxlen:
        old = _dedupe_q.popleft()
        _dedupe.discard(old)
    return True

# -----------------------------
# Dexscreener enrichment (optional but enabled by default)
# -----------------------------
DEXSCREENER_ENABLED = os.getenv("DEXSCREENER_ENABLED", "1").strip() not in ("0", "false", "False")
DEX_TIMEOUT = float(os.getenv("DEX_TIMEOUT", "12"))

dex_session = requests.Session()
DEX_TOKEN_PAIRS_URL = "https://api.dexscreener.com/token-pairs/v1/{chain}/{token}"

def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return default if cur is None else cur

def _to_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0

def dex_chain_from_network(network: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return "base"
    return "ethereum"

def dex_pick_best_pair(pairs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not pairs:
        return None
    def liq_usd(p: Dict[str, Any]) -> float:
        return _to_float(_safe_get(p, "liquidity", "usd", default=0))
    return max(pairs, key=liq_usd)

def dex_enrich(chain: str, token_addr: str) -> Optional[Dict[str, Any]]:
    if not DEXSCREENER_ENABLED:
        return None
    if not token_addr or token_addr in ("native", "unknown"):
        return None
    if not token_addr.startswith("0x"):
        return None

    url = DEX_TOKEN_PAIRS_URL.format(chain=chain, token=token_addr)
    r = dex_session.get(url, timeout=DEX_TIMEOUT)
    if r.status_code != 200:
        return None
    pairs = r.json()
    if not isinstance(pairs, list) or not pairs:
        return None

    best = dex_pick_best_pair(pairs)
    if not best:
        return None

    return {
        "url": best.get("url") or f"https://dexscreener.com/{chain}/{token_addr}",
        "priceUsd": best.get("priceUsd"),
        "liqUsd": _to_float(_safe_get(best, "liquidity", "usd", default=0)),
        "vol5m": _to_float(_safe_get(best, "volume", "m5", default=0)),
        "vol1h": _to_float(_safe_get(best, "volume", "h1", default=0)),
    }

# -----------------------------
# Explorer links
# -----------------------------
def explorer_tx(network: str, tx: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return f"https://basescan.org/tx/{tx}"
    return f"https://etherscan.io/tx/{tx}"

# -----------------------------
# Alchemy Address Activity parsing
# -----------------------------
def parse_alchemy_address_activity(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Expected: { "type":"ADDRESS_ACTIVITY", "event": { "network":"...", "activity":[...] } }
    if not isinstance(payload, dict):
        return []
    if payload.get("type") != "ADDRESS_ACTIVITY":
        return []
    event = payload.get("event") or {}
    activity = event.get("activity") or []
    return activity if isinstance(activity, list) else []

def group_activity_by_hash(activity: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_hash: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in activity:
        h = a.get("hash")
        if isinstance(h, str) and h.startswith("0x"):
            by_hash[h].append(a)
    return by_hash

def safe_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0

def asset_key(a: Dict[str, Any]) -> Tuple[str, str]:
    sym = (a.get("asset") or "UNKNOWN").upper()
    rc = a.get("rawContract") or {}
    addr = (rc.get("address") or "").lower()
    if not addr and sym == "ETH":
        addr = "native"
    if not addr:
        addr = "unknown"
    return addr, sym

def find_tracked_wallet(items: List[Dict[str, Any]]) -> Optional[str]:
    # Find a watched wallet involved in this tx (from/to)
    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        if frm and is_tracked(frm):
            return frm
        if to and is_tracked(to):
            return to
    return None

def summarize_for_wallet(items: List[Dict[str, Any]], wallet: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    For the tracked wallet: net inflows/outflows by asset.
    Returns:
      spent   = most-negative net flow (amount out)
      received= largest positive net flow (amount in)
    """
    w = (wallet or "").lower()
    net: Dict[Tuple[str, str], float] = defaultdict(float)

    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        addr, sym = asset_key(a)
        amt = safe_float(a.get("value") or 0)

        if to == w:
            net[(addr, sym)] += amt
        if frm == w:
            net[(addr, sym)] -= amt

    spent = None
    received = None

    neg = [(k, v) for k, v in net.items() if v < 0]
    pos = [(k, v) for k, v in net.items() if v > 0]

    if neg:
        (addr, sym), v = min(neg, key=lambda kv: kv[1])  # most negative
        spent = {"address": addr, "symbol": sym, "amount": abs(v)}
    if pos:
        (addr, sym), v = max(pos, key=lambda kv: kv[1])  # biggest incoming
        received = {"address": addr, "symbol": sym, "amount": v}

    return spent, received

def classify_side(spent: Optional[Dict[str, Any]], received: Optional[Dict[str, Any]]) -> str:
    if spent and received:
        s_spent = (spent.get("symbol") or "").upper()
        s_recv = (received.get("symbol") or "").upper()

        if s_spent in QUOTE_SYMBOLS and s_recv not in QUOTE_SYMBOLS:
            return "BUY"
        if s_recv in QUOTE_SYMBOLS and s_spent not in QUOTE_SYMBOLS:
            return "SELL"
        return "SWAP"
    return "TRANSFER"

# -----------------------------
# App + summary counters
# -----------------------------
app = FastAPI()

summary = {
    "received": 0,
    "sent": 0,
    "ignored": 0,
    # reasons:
    "bad_type": 0,
    "no_wallet": 0,
    "untracked": 0,
    "infra_block": 0,
    "transfer_ignored": 0,
    "too_small": 0,
    "dedupe": 0,
    "empty_msg": 0,
    "exceptions": 0,
    "last_sent_ts": 0,
}

def log_summary(tag: str) -> None:
    log.info("%s_summary=%s", tag, json.dumps(summary, separators=(",", ":")))

@app.get("/")
def root():
    return {
        "ok": True,
        "service": "wallet-webhook",
        "watch_evm": len(WATCH_WALLETS_EVM),
        "ignore_transfers": IGNORE_TRANSFERS,
        "dexscreener": DEXSCREENER_ENABLED,
    }

@app.get("/health")
def health():
    return {"ok": True, "summary": summary}

# -----------------------------
# EVM webhook (Alchemy)
# -----------------------------
@app.post("/webhook/evm")
async def webhook_evm(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_alchemy_signature: Optional[str] = Header(default=None, alias="X-Alchemy-Signature"),
):
    raw = await request.body()

    # Optional shared secret (only if you set EVM_WEBHOOK_SECRET)
    check_secret(authorization, EVM_WEBHOOK_SECRET)

    # Signature verify
    verify_alchemy_signature(raw, x_alchemy_signature)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    summary["received"] += 1

    event = payload.get("event") or {}
    network = event.get("network") or "ETH_MAINNET"
    chain = dex_chain_from_network(network)

    activity = parse_alchemy_address_activity(payload)
    if not activity:
        summary["bad_type"] += 1
        log_summary("alchemy")
        return {"ok": True, "received": 0, "sent": 0}

    by_hash = group_activity_by_hash(activity)

    sent = 0
    for tx_hash, items in by_hash.items():
        try:
            tracked_wallet = find_tracked_wallet(items)
            if not tracked_wallet:
                summary["no_wallet"] += 1
                continue

            tracked_wallet_lc = tracked_wallet.lower()

            # If user set a watchlist, enforce it
            if WATCH_WALLETS_EVM and tracked_wallet_lc not in WATCH_WALLETS_EVM:
                summary["untracked"] += 1
                continue

            # Blocklist infra addresses so you don't get spam if you accidentally track routers/contracts
            if tracked_wallet_lc in INFRA_BLOCKLIST:
                summary["infra_block"] += 1
                summary["ignored"] += 1
                continue

            spent, received = summarize_for_wallet(items, tracked_wallet_lc)
            side = classify_side(spent, received)

            # NEW: ignore TRANSFER spam (recommended)
            if IGNORE_TRANSFERS and side == "TRANSFER":
                summary["transfer_ignored"] += 1
                summary["ignored"] += 1
                continue

            # Optional: ignore tiny native transfers if you ever turn off IGNORE_TRANSFERS
            if side == "TRANSFER" and MIN_NATIVE > 0 and received:
                if received.get("symbol", "").upper() in ("ETH", "WETH") and received.get("address") == "native":
                    if float(received.get("amount", 0)) < MIN_NATIVE:
                        summary["too_small"] += 1
                        summary["ignored"] += 1
                        continue

            dedupe_key = f"{network}:{tracked_wallet_lc}:{tx_hash}:{side}"
            if not remember_once(dedupe_key):
                summary["dedupe"] += 1
                summary["ignored"] += 1
                continue

            # Dexscreener enrichment (token side)
            # For BUY: enrich received token if it’s not quote/native
            # For SELL: enrich spent token if it’s not quote/native
            token_to_enrich = None
            if side == "BUY" and received and received.get("symbol", "").upper() not in QUOTE_SYMBOLS:
                token_to_enrich = received.get("address")
            elif side == "SELL" and spent and spent.get("symbol", "").upper() not in QUOTE_SYMBOLS:
                token_to_enrich = spent.get("address")
            elif side == "SWAP":
                # pick the non-quote leg if possible
                if received and received.get("symbol", "").upper() not in QUOTE_SYMBOLS:
                    token_to_enrich = received.get("address")
                elif spent and spent.get("symbol", "").upper() not in QUOTE_SYMBOLS:
                    token_to_enrich = spent.get("address")

            dex = dex_enrich(chain, token_to_enrich) if token_to_enrich else None

            # Build message
            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡" if side == "SWAP" else "⚪"
            chain_name = "base" if chain == "base" else "ethereum"

            lines = []
            lines.append(f"{emoji} {side} ({chain_name})")
            lines.append(f"Wallet: {tracked_wallet_lc}")

            if spent:
                lines.append(f"Spent: {spent['amount']:.6g} {spent['symbol']} ({spent['address']})")
            if received:
                lines.append(f"Received: {received['amount']:.6g} {received['symbol']} ({received['address']})")

            if dex:
                # Keep it compact but useful
                price = dex.get("priceUsd")
                liq = dex.get("liqUsd", 0.0)
                v5 = dex.get("vol5m", 0.0)
                v1 = dex.get("vol1h", 0.0)
                lines.append(f"Dexscreener: {dex.get('url')}")
                if price is not None:
                    try:
                        lines.append(f"Price: ${float(price):.8f} | Liquidity: ${liq:,.0f}")
                    except Exception:
                        lines.append(f"Price: {price} | Liquidity: ${liq:,.0f}")
                else:
                    lines.append(f"Liquidity: ${liq:,.0f}")
                lines.append(f"Vol(5m): ${v5:,.0f} | Vol(1h): ${v1:,.0f}")

            lines.append(f"Tx: {tx_hash}")
            lines.append(f"Explorer: {explorer_tx(network, tx_hash)}")

            msg = "\n".join(lines).strip()
            if not msg:
                summary["empty_msg"] += 1
                summary["ignored"] += 1
                continue

            tg_send(msg)
            sent += 1
            summary["sent"] += 1
            summary["last_sent_ts"] = int(time.time())

        except Exception as e:
            summary["exceptions"] += 1
            summary["ignored"] += 1
            log.exception("evm processing error: %s", e)

    if sent == 0:
        summary["ignored"] += 1

    log_summary("alchemy")
    return {"ok": True, "received": len(by_hash), "sent": sent, "ignored": (len(by_hash) - sent)}

# -----------------------------
# Helpful: echo summary quickly
# -----------------------------
@app.get("/debug/summary")
def debug_summary():
    # Same idea as your "helius_summary" log, but as an endpoint too
    return {"ok": True, "alchemy_summary": summary, "watch_evm": len(WATCH_WALLETS_EVM)}

# -----------------------------
# Error handler
# -----------------------------
@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})
