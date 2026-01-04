# app.py
# FastAPI webhook receiver for:
#  - Alchemy (EVM): POST /webhook/evm
#  - Helius (Solana): POST /helius   (and /webhook/solana alias)
#
# Features:
#  - Telegram alerts
#  - Optional secrets (Authorization header)
#  - Optional Alchemy signature verification (X-Alchemy-Signature)
#  - Wallet allowlists (WATCH_WALLETS_EVM, WATCH_WALLETS_SOLANA)
#  - BUY/SELL/SWAP classification (ignores TRANSFER/NFT by default)
#  - Dexscreener enrichment (price/liquidity/vol + link)
#  - Jupiter + Phantom links for Solana swaps
#  - Summary counters + log lines: alchemy_summary=..., helius_summary=...

import os
import json
import time
import hmac
import hashlib
import logging
import random
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict, deque
from urllib.parse import quote as urlquote

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

def parse_csv_set(name: str) -> set:
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
# Shared secret auth (optional)
# -----------------------------
EVM_WEBHOOK_SECRET = os.getenv("EVM_WEBHOOK_SECRET", "").strip()
HELIUS_WEBHOOK_SECRET = os.getenv("HELIUS_WEBHOOK_SECRET", "").strip()

def check_secret(auth_header: Optional[str], expected: str) -> None:
    if not expected:
        return
    if not auth_header or auth_header.strip() != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")

# -----------------------------
# Security (Alchemy Signature) - optional
# -----------------------------
ALCHEMY_SIGNING_KEY = os.getenv("ALCHEMY_SIGNING_KEY", "").encode()

def verify_alchemy_signature(raw_body: bytes, sig_header: Optional[str]) -> None:
    """
    Verify X-Alchemy-Signature:
      expected = HMAC_SHA256(raw_body, ALCHEMY_SIGNING_KEY).hexdigest()
    If ALCHEMY_SIGNING_KEY isn't set, do not block (useful for testing).
    """
    if not ALCHEMY_SIGNING_KEY:
        return
    if not sig_header:
        raise HTTPException(status_code=401, detail="Missing X-Alchemy-Signature")

    sig = sig_header.strip()
    if sig.startswith("sha256="):
        sig = sig.split("=", 1)[1].strip()

    expected = hmac.new(ALCHEMY_SIGNING_KEY, raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.lower(), expected.lower()):
        raise HTTPException(status_code=401, detail="Invalid X-Alchemy-Signature")

# -----------------------------
# Watchlists
# -----------------------------
WATCH_WALLETS_EVM = {w.lower() for w in parse_csv_set("WATCH_WALLETS_EVM")}
WATCH_WALLETS_SOLANA = set(
    w for w in os.getenv("WATCH_WALLETS_SOLANA", "").replace(" ", "").split(",") if w
)

def is_tracked_evm(wallet: str) -> bool:
    if not WATCH_WALLETS_EVM:
        return True
    return (wallet or "").lower() in WATCH_WALLETS_EVM

def is_tracked_solana(wallet: str) -> bool:
    # If you forgot to set WATCH_WALLETS_SOLANA, don't block everything
    return (not WATCH_WALLETS_SOLANA) or (wallet in WATCH_WALLETS_SOLANA)

# -----------------------------
# Filters / behavior
# -----------------------------
IGNORE_TRANSFERS_EVM = os.getenv("IGNORE_TRANSFERS_EVM", "1").strip() not in ("0", "false", "False")
IGNORE_TRANSFERS_SOL = os.getenv("IGNORE_TRANSFERS_SOL", "1").strip() not in ("0", "false", "False")

# Optional ignore list by Helius "type"
IGNORE_HELIUS_TYPES = {x.strip().upper() for x in os.getenv(
    "IGNORE_HELIUS_TYPES",
    "NFT_SALE,NFT_MINT,NFT_BID,NFT_LISTING,NFT_CANCEL_LISTING,COMPRESSED_NFT_MINT"
).split(",") if x.strip()}

# Optional minimum trade sizing (Solana)
MIN_SOL_TRADE = float(os.getenv("MIN_SOL_TRADE", "0"))  # e.g. 0.05 to ignore tiny swaps
MIN_USDC_TRADE = float(os.getenv("MIN_USDC_TRADE", "0"))  # optional

# EVM quote symbols
QUOTE_SYMBOLS_EVM = {s.strip().upper() for s in os.getenv("QUOTE_SYMBOLS_EVM", "ETH,WETH,USDC,USDT,DAI").split(",") if s.strip()}

# Solana quote symbols + mints
SOL_MINT = "So11111111111111111111111111111111111111112"  # wSOL mint (often used in swaps)
USDC_MINT_SOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT_MINT_SOL = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

KNOWN_SOL_MINT_SYMBOL = {
    SOL_MINT: "SOL",
    USDC_MINT_SOL: "USDC",
    USDT_MINT_SOL: "USDT",
}

QUOTE_SYMBOLS_SOL = {"SOL", "USDC", "USDT"}

# -----------------------------
# Infra blocklist safety net (EVM)
# -----------------------------
INFRA_BLOCKLIST = {x.lower() for x in parse_csv_set("INFRA_BLOCKLIST")}
if not INFRA_BLOCKLIST:
    INFRA_BLOCKLIST = {
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap SwapRouter02
        "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",  # Uniswap UniversalRouter
        "0x000000000022d473030f116ddee9f6b43ac78ba3",  # Permit2
        "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch Router v5
        "0x9008d19f58aabd9ed0d60971565aa8510560ab41",  # CoW settlement
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
# Dexscreener enrichment
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
def explorer_tx_evm(network: str, tx: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return f"https://basescan.org/tx/{tx}"
    return f"https://etherscan.io/tx/{tx}"

def explorer_tx_solana(sig: str) -> str:
    return f"https://solscan.io/tx/{sig}"

# -----------------------------
# Solana swap helper links
# -----------------------------
def jup_swap_url(in_token: Dict[str, str], out_token: Dict[str, str]) -> str:
    def part(tok: Dict[str, str]) -> str:
        sym = (tok.get("symbol") or "").upper()
        addr = tok.get("address") or ""
        if sym in QUOTE_SYMBOLS_SOL:
            return sym
        # if addr missing, fall back to symbol
        return addr or sym or "SOL"
    return f"https://jup.ag/swap/{part(in_token)}-{part(out_token)}"

def phantom_browse(url: str) -> str:
    # Opens a webpage inside Phantom's in-app browser
    return f"https://phantom.app/ul/browse/{urlquote(url, safe='')}"


# =============================
# EVM (Alchemy) parsing helpers
# =============================
def parse_alchemy_address_activity(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
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

def asset_key_evm(a: Dict[str, Any]) -> Tuple[str, str]:
    sym = (a.get("asset") or "UNKNOWN").upper()
    rc = a.get("rawContract") or {}
    addr = (rc.get("address") or "").lower()
    if not addr and sym == "ETH":
        addr = "native"
    if not addr:
        addr = "unknown"
    return addr, sym

def find_tracked_wallet_evm(items: List[Dict[str, Any]]) -> Optional[str]:
    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        if frm and is_tracked_evm(frm):
            return frm
        if to and is_tracked_evm(to):
            return to
    return None

def summarize_for_wallet_evm(items: List[Dict[str, Any]], wallet: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    w = (wallet or "").lower()
    net: Dict[Tuple[str, str], float] = defaultdict(float)

    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        addr, sym = asset_key_evm(a)
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
        (addr, sym), v = min(neg, key=lambda kv: kv[1])
        spent = {"address": addr, "symbol": sym, "amount": abs(v)}
    if pos:
        (addr, sym), v = max(pos, key=lambda kv: kv[1])
        received = {"address": addr, "symbol": sym, "amount": v}

    return spent, received

def classify_side_evm(spent: Optional[Dict[str, Any]], received: Optional[Dict[str, Any]]) -> str:
    if spent and received:
        s_spent = (spent.get("symbol") or "").upper()
        s_recv = (received.get("symbol") or "").upper()

        if s_spent in QUOTE_SYMBOLS_EVM and s_recv not in QUOTE_SYMBOLS_EVM:
            return "BUY"
        if s_recv in QUOTE_SYMBOLS_EVM and s_spent not in QUOTE_SYMBOLS_EVM:
            return "SELL"
        return "SWAP"
    return "TRANSFER"

def dex_chain_from_network(network: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return "base"
    return "ethereum"


# =============================
# Solana (Helius) parsing helpers
# =============================
LAMPORTS_PER_SOL = 1_000_000_000

def lamports_to_sol(x: Any) -> float:
    try:
        v = float(x)
    except Exception:
        return 0.0
    # Helius nativeTransfers.amount is typically lamports
    if v > 1e6:
        return v / LAMPORTS_PER_SOL
    return v

def parse_helius_payload(payload: Any) -> List[Dict[str, Any]]:
    # Helius webhook often sends a LIST of transactions
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        # sometimes wrapped
        if isinstance(payload.get("transactions"), list):
            return [x for x in payload["transactions"] if isinstance(x, dict)]
        return [payload]
    return []

def sol_symbol_for_mint(mint: str) -> str:
    if mint in KNOWN_SOL_MINT_SYMBOL:
        return KNOWN_SOL_MINT_SYMBOL[mint]
    return "TOKEN"

def pick_tracked_wallet_solana(tx: Dict[str, Any]) -> Optional[str]:
    # Look through nativeTransfers + tokenTransfers for any tracked wallet
    nts = tx.get("nativeTransfers") or []
    tts = tx.get("tokenTransfers") or []

    def scan_transfers(arr: List[Dict[str, Any]]) -> Optional[str]:
        for t in arr:
            frm = t.get("fromUserAccount") or ""
            to = t.get("toUserAccount") or ""
            if frm and is_tracked_solana(frm):
                return frm
            if to and is_tracked_solana(to):
                return to
        return None

    w = scan_transfers(nts)
    if w:
        return w
    w = scan_transfers(tts)
    if w:
        return w

    # fallback: feePayer
    fp = tx.get("feePayer") or ""
    if fp and is_tracked_solana(fp):
        return fp
    return None

def sol_net_flows(tx: Dict[str, Any], wallet: str) -> Dict[Tuple[str, str], float]:
    """
    Returns net flow per (address, symbol) for THIS wallet:
      + = received, - = spent
    """
    w = wallet
    net: Dict[Tuple[str, str], float] = defaultdict(float)

    nts = tx.get("nativeTransfers") or []
    for t in nts:
        frm = t.get("fromUserAccount") or ""
        to = t.get("toUserAccount") or ""
        amt_sol = lamports_to_sol(t.get("amount") or 0)
        if amt_sol == 0:
            continue
        if to == w:
            net[("native", "SOL")] += amt_sol
        if frm == w:
            net[("native", "SOL")] -= amt_sol

    tts = tx.get("tokenTransfers") or []
    for t in tts:
        frm = t.get("fromUserAccount") or ""
        to = t.get("toUserAccount") or ""
        mint = t.get("mint") or "unknown"
        sym = t.get("tokenSymbol") or KNOWN_SOL_MINT_SYMBOL.get(mint) or "TOKEN"
        sym = str(sym).upper()
        amt = t.get("tokenAmount")
        if amt is None:
            # fallback raw amount if present
            amt = t.get("rawTokenAmount", {}).get("tokenAmount")
        try:
            amt = float(amt)
        except Exception:
            amt = 0.0
        if amt == 0:
            continue

        if to == w:
            net[(mint, sym)] += amt
        if frm == w:
            net[(mint, sym)] -= amt

    return net

def pick_spent_received(net: Dict[Tuple[str, str], float]) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    neg = [(k, v) for k, v in net.items() if v < 0]
    pos = [(k, v) for k, v in net.items() if v > 0]
    spent = None
    received = None
    if neg:
        (addr, sym), v = min(neg, key=lambda kv: kv[1])  # most negative
        spent = {"address": addr, "symbol": sym, "amount": abs(v)}
    if pos:
        (addr, sym), v = max(pos, key=lambda kv: kv[1])
        received = {"address": addr, "symbol": sym, "amount": v}
    return spent, received

def classify_side_sol(spent: Optional[Dict[str, Any]], received: Optional[Dict[str, Any]]) -> str:
    if spent and received:
        s_spent = (spent.get("symbol") or "").upper()
        s_recv = (received.get("symbol") or "").upper()

        if s_spent in QUOTE_SYMBOLS_SOL and s_recv not in QUOTE_SYMBOLS_SOL:
            return "BUY"
        if s_recv in QUOTE_SYMBOLS_SOL and s_spent not in QUOTE_SYMBOLS_SOL:
            return "SELL"
        return "SWAP"
    return "TRANSFER"

def too_small_sol(spent: Optional[Dict[str, Any]], received: Optional[Dict[str, Any]]) -> bool:
    # Optional minimum trade filters
    if MIN_SOL_TRADE > 0:
        for leg in (spent, received):
            if not leg:
                continue
            if (leg.get("symbol") or "").upper() == "SOL" and float(leg.get("amount", 0)) < MIN_SOL_TRADE:
                return True
    if MIN_USDC_TRADE > 0:
        for leg in (spent, received):
            if not leg:
                continue
            if (leg.get("symbol") or "").upper() == "USDC" and float(leg.get("amount", 0)) < MIN_USDC_TRADE:
                return True
    return False


# =============================
# App + summaries
# =============================
app = FastAPI()

alchemy_summary = {
    "received": 0, "sent": 0, "ignored": 0,
    "bad_type": 0, "no_wallet": 0, "untracked": 0, "infra_block": 0,
    "transfer_ignored": 0, "too_small": 0, "dedupe": 0, "empty_msg": 0, "exceptions": 0,
    "last_sent_ts": 0,
}

helius_summary = {
    "received": 0, "sent": 0, "ignored": 0,
    "bad_type": 0, "no_wallet": 0, "untracked": 0,
    "transfer_ignored": 0, "type_ignored": 0, "too_small": 0, "dedupe": 0, "empty_msg": 0, "exceptions": 0,
    "hold_started": 0,  # kept for compatibility with your old summary key
    "last_sent_ts": 0,
}

def log_summary(tag: str, summary_obj: Dict[str, Any]) -> None:
    log.info("%s_summary=%s", tag, json.dumps(summary_obj, separators=(",", ":")))

@app.get("/")
def root():
    return {
        "ok": True,
        "service": "wallet-webhook",
        "watch_evm": len(WATCH_WALLETS_EVM),
        "watch_solana": len(WATCH_WALLETS_SOLANA),
        "ignore_transfers_evm": IGNORE_TRANSFERS_EVM,
        "ignore_transfers_sol": IGNORE_TRANSFERS_SOL,
        "dexscreener": DEXSCREENER_ENABLED,
        "paths": {
            "alchemy_evm": "/webhook/evm",
            "helius_solana": "/helius",
            "helius_alias": "/webhook/solana",
        }
    }

@app.get("/health")
def health():
    return {"ok": True, "alchemy_summary": alchemy_summary, "helius_summary": helius_summary}

@app.get("/debug/summary")
def debug_summary():
    return {"ok": True, "alchemy_summary": alchemy_summary, "helius_summary": helius_summary}


# =============================
# EVM webhook (Alchemy)
# =============================
@app.post("/webhook/evm")
async def webhook_evm(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_alchemy_signature: Optional[str] = Header(default=None, alias="X-Alchemy-Signature"),
):
    raw = await request.body()
    check_secret(authorization, EVM_WEBHOOK_SECRET)
    verify_alchemy_signature(raw, x_alchemy_signature)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    alchemy_summary["received"] += 1

    activity = parse_alchemy_address_activity(payload)
    if not activity:
        alchemy_summary["bad_type"] += 1
        log_summary("alchemy", alchemy_summary)
        return {"ok": True, "received": 0, "sent": 0}

    event = payload.get("event") or {}
    network = event.get("network") or "ETH_MAINNET"
    chain = dex_chain_from_network(network)

    by_hash = group_activity_by_hash(activity)
    sent = 0

    for tx_hash, items in by_hash.items():
        try:
            tracked_wallet = find_tracked_wallet_evm(items)
            if not tracked_wallet:
                alchemy_summary["no_wallet"] += 1
                continue

            w = tracked_wallet.lower()

            if WATCH_WALLETS_EVM and w not in WATCH_WALLETS_EVM:
                alchemy_summary["untracked"] += 1
                continue

            if w in INFRA_BLOCKLIST:
                alchemy_summary["infra_block"] += 1
                alchemy_summary["ignored"] += 1
                continue

            spent, received = summarize_for_wallet_evm(items, w)
            side = classify_side_evm(spent, received)

            if IGNORE_TRANSFERS_EVM and side == "TRANSFER":
                alchemy_summary["transfer_ignored"] += 1
                alchemy_summary["ignored"] += 1
                continue

            dedupe_key = f"{network}:{w}:{tx_hash}:{side}"
            if not remember_once(dedupe_key):
                alchemy_summary["dedupe"] += 1
                alchemy_summary["ignored"] += 1
                continue

            # Dex enrichment: enrich token leg when possible
            token_to_enrich = None
            if side == "BUY" and received and received.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                token_to_enrich = received.get("address")
            elif side == "SELL" and spent and spent.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                token_to_enrich = spent.get("address")
            elif side == "SWAP":
                if received and received.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                    token_to_enrich = received.get("address")
                elif spent and spent.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                    token_to_enrich = spent.get("address")

            dex = dex_enrich(chain, token_to_enrich) if token_to_enrich else None

            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡" if side == "SWAP" else "⚪"
            chain_name = "base" if chain == "base" else "ethereum"

            lines = [f"{emoji} {side} ({chain_name})", f"Wallet: {w}"]
            if spent:
                lines.append(f"Spent: {spent['amount']:.6g} {spent['symbol']} ({spent['address']})")
            if received:
                lines.append(f"Received: {received['amount']:.6g} {received['symbol']} ({received['address']})")

            if dex:
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
            lines.append(f"Explorer: {explorer_tx_evm(network, tx_hash)}")

            msg = "\n".join(lines).strip()
            if not msg:
                alchemy_summary["empty_msg"] += 1
                alchemy_summary["ignored"] += 1
                continue

            tg_send(msg)
            sent += 1
            alchemy_summary["sent"] += 1
            alchemy_summary["last_sent_ts"] = int(time.time())

        except Exception as e:
            alchemy_summary["exceptions"] += 1
            alchemy_summary["ignored"] += 1
            log.exception("evm processing error: %s", e)

    if sent == 0:
        alchemy_summary["ignored"] += 1

    log_summary("alchemy", alchemy_summary)
    return {"ok": True, "received": len(by_hash), "sent": sent, "ignored": (len(by_hash) - sent)}


# =============================
# Solana webhook (Helius)
# =============================
async def _handle_helius(request: Request, authorization: Optional[str]) -> Dict[str, Any]:
    raw = await request.body()
    check_secret(authorization, HELIUS_WEBHOOK_SECRET)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    helius_summary["received"] += 1

    txs = parse_helius_payload(payload)
    if not txs:
        helius_summary["bad_type"] += 1
        log_summary("helius", helius_summary)
        return {"ok": True, "received": 0, "sent": 0}

    sent = 0

    for tx in txs:
        try:
            sig = tx.get("signature") or tx.get("transactionSignature") or ""
            if not sig:
                helius_summary["bad_type"] += 1
                continue

            tx_type = (tx.get("type") or "").upper()
            if tx_type in IGNORE_HELIUS_TYPES:
                helius_summary["type_ignored"] += 1
                helius_summary["ignored"] += 1
                continue

            wallet = pick_tracked_wallet_solana(tx)
            if not wallet:
                helius_summary["no_wallet"] += 1
                continue

            if WATCH_WALLETS_SOLANA and wallet not in WATCH_WALLETS_SOLANA:
                helius_summary["untracked"] += 1
                continue

            net = sol_net_flows(tx, wallet)
            spent, received = pick_spent_received(net)
            side = classify_side_sol(spent, received)

            # only alert BUY/SELL/SWAP by default
            if IGNORE_TRANSFERS_SOL and side == "TRANSFER":
                helius_summary["transfer_ignored"] += 1
                helius_summary["ignored"] += 1
                continue

            if too_small_sol(spent, received):
                helius_summary["too_small"] += 1
                helius_summary["ignored"] += 1
                continue

            dedupe_key = f"solana:{wallet}:{sig}:{side}"
            if not remember_once(dedupe_key):
                helius_summary["dedupe"] += 1
                helius_summary["ignored"] += 1
                continue

            # Dex enrichment: enrich the "token leg" if possible
            token_to_enrich = None
            if side == "BUY" and received and (received.get("symbol") or "").upper() not in QUOTE_SYMBOLS_SOL:
                token_to_enrich = received.get("address")
            elif side == "SELL" and spent and (spent.get("symbol") or "").upper() not in QUOTE_SYMBOLS_SOL:
                token_to_enrich = spent.get("address")
            elif side == "SWAP":
                if received and (received.get("symbol") or "").upper() not in QUOTE_SYMBOLS_SOL:
                    token_to_enrich = received.get("address")
                elif spent and (spent.get("symbol") or "").upper() not in QUOTE_SYMBOLS_SOL:
                    token_to_enrich = spent.get("address")

            dex = dex_enrich("solana", token_to_enrich) if token_to_enrich else None

            # Links: Jupiter + Phantom (if we have both legs)
            jup = None
            ph = None
            if spent and received:
                in_tok = {"address": spent.get("address") or "", "symbol": (spent.get("symbol") or "").upper()}
                out_tok = {"address": received.get("address") or "", "symbol": (received.get("symbol") or "").upper()}

                # normalize native SOL
                if in_tok["address"] == "native":
                    in_tok["symbol"] = "SOL"
                if out_tok["address"] == "native":
                    out_tok["symbol"] = "SOL"

                jup = jup_swap_url(in_tok, out_tok)
                ph = phantom_browse(jup)

            desc = tx.get("description") or ""
            source = tx.get("source") or ""
            timestamp = tx.get("timestamp")

            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡" if side == "SWAP" else "⚪"

            lines = []
            lines.append(f"{emoji} {side} (solana)")
            lines.append(f"Wallet: {wallet}")

            if spent:
                lines.append(f"Spent: {spent['amount']:.6g} {spent['symbol']} ({spent['address']})")
            if received:
                lines.append(f"Received: {received['amount']:.6g} {received['symbol']} ({received['address']})")

            if desc:
                lines.append(f"Desc: {desc}")
            if source:
                lines.append(f"Source: {source}")
            if tx_type:
                lines.append(f"Type: {tx_type}")

            if jup:
                lines.append(f"Jupiter: {jup}")
            if ph:
                lines.append(f"Phantom: {ph}")

            if dex:
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

            lines.append(f"Sig: {sig}")
            lines.append(f"Explorer: {explorer_tx_solana(sig)}")

            msg = "\n".join(lines).strip()
            if not msg:
                helius_summary["empty_msg"] += 1
                helius_summary["ignored"] += 1
                continue

            tg_send(msg)
            sent += 1
            helius_summary["sent"] += 1
            helius_summary["last_sent_ts"] = int(time.time())

        except Exception as e:
            helius_summary["exceptions"] += 1
            helius_summary["ignored"] += 1
            log.exception("helius processing error: %s", e)

    if sent == 0:
        helius_summary["ignored"] += 1

    log_summary("helius", helius_summary)
    return {"ok": True, "received": len(txs), "sent": sent, "ignored": (len(txs) - sent)}

@app.post("/helius")
async def helius_webhook(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    return await _handle_helius(request, authorization)

# aliases (helpful if you previously used other paths)
@app.post("/helius/")
async def helius_webhook_slash(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    return await _handle_helius(request, authorization)

@app.post("/webhook/solana")
async def helius_webhook_alias(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    return await _handle_helius(request, authorization)

@app.post("/webhook/solana/")
async def helius_webhook_alias_slash(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    return await _handle_helius(request, authorization)

# -----------------------------
# Error handler
# -----------------------------
@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})

