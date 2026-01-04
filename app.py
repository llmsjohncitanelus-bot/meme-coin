# app.py
# FastAPI webhook receiver:
# - Solana: Helius enhanced webhooks at POST /helius (Authorization secret optional)
# - EVM: Alchemy Address Activity webhooks at POST /webhook/evm (X-Alchemy-Signature optional)
# Sends Telegram alerts for BUY / SELL / SWAP with optional Dexscreener enrichment
# Adds Phantom links (token + in-app + swap) for Solana/Ethereum/Base
# Adds Jupiter link for Solana when token symbol is known
# Adds "why ignored" counters (summary endpoints + log summaries)

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

def safe_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0

def _to_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0

def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return default if cur is None else cur

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = getenv_required("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = int(getenv_required("TELEGRAM_CHAT_ID"))

TG_MIN_INTERVAL = float(os.getenv("TG_MIN_INTERVAL", "1.0"))  # seconds between messages
TG_DISABLE_PREVIEW = os.getenv("TG_DISABLE_PREVIEW", "0").strip() in ("1", "true", "True")

_last_tg_ts = 0.0
tg_session = requests.Session()
TG_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

def tg_send(text: str, silent: bool = False) -> None:
    """Telegram send with simple rate limit + optional link previews."""
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
            # IMPORTANT: previews OFF removes the Phantom preview card.
            "disable_web_page_preview": bool(TG_DISABLE_PREVIEW),
        },
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data)
    _last_tg_ts = time.time()

# -----------------------------
# Secrets / auth helpers
# -----------------------------
def check_secret(auth_header: Optional[str], expected: str) -> None:
    if not expected:
        return
    if not auth_header or auth_header.strip() != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")

# -----------------------------
# Watchlists + Labels
# -----------------------------
WATCH_WALLETS_SOL = {w.strip() for w in parse_csv_set("WATCH_WALLETS_SOL")}
WATCH_WALLETS_EVM = {w.lower() for w in parse_csv_set("WATCH_WALLETS_EVM")}

def is_tracked_sol(addr: str) -> bool:
    # If not set, don't block everything
    return (not WATCH_WALLETS_SOL) or (addr in WATCH_WALLETS_SOL)

def is_tracked_evm(addr: str) -> bool:
    return (not WATCH_WALLETS_EVM) or ((addr or "").lower() in WATCH_WALLETS_EVM)

# Optional label maps (JSON): {"0xabc...":"Binance 14","7Dv...":"My Whale"}
LABELS_EVM: Dict[str, str] = {}
LABELS_SOL: Dict[str, str] = {}

def _load_labels() -> None:
    global LABELS_EVM, LABELS_SOL
    try:
        raw_evm = os.getenv("LABELS_EVM_JSON", "").strip()
        if raw_evm:
            LABELS_EVM = {k.lower(): str(v) for k, v in json.loads(raw_evm).items()}
    except Exception:
        LABELS_EVM = {}
    try:
        raw_sol = os.getenv("LABELS_SOL_JSON", "").strip()
        if raw_sol:
            LABELS_SOL = {k: str(v) for k, v in json.loads(raw_sol).items()}
    except Exception:
        LABELS_SOL = {}

_load_labels()

def label_evm(addr: str) -> str:
    a = (addr or "").lower()
    return LABELS_EVM.get(a, a)

def label_sol(addr: str) -> str:
    return LABELS_SOL.get(addr, addr)

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

def dex_pick_best_pair(pairs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not pairs:
        return None
    def liq_usd(p: Dict[str, Any]) -> float:
        return _to_float(_safe_get(p, "liquidity", "usd", default=0))
    return max(pairs, key=liq_usd)

def dex_enrich(chain: str, token_addr: str) -> Optional[Dict[str, Any]]:
    """
    chain: "solana" | "ethereum" | "base"
    token_addr:
      - solana mint (base58)
      - evm token (0x...)
    """
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
# Phantom + Jupiter links
# -----------------------------
INCLUDE_PHANTOM_LINKS = os.getenv("INCLUDE_PHANTOM_LINKS", "1").strip() not in ("0", "false", "False")
INCLUDE_JUPITER_LINKS = os.getenv("INCLUDE_JUPITER_LINKS", "1").strip() not in ("0", "false", "False")

def phantom_token_link(chain: str, token: str) -> str:
    # chain: solana|ethereum|base
    return f"https://phantom.com/tokens/{chain}/{token}"

def phantom_inapp_token(chain: str, token: str) -> str:
    # deep link (same style you had): token=solana%3A<address>
    return f"https://phantom.app/ul/v1/fungible?token={chain}%3A{token}"

def phantom_swap_link(chain: str, token: str) -> str:
    # deep link (same style you had): sell=solana%3A<address>
    return f"https://phantom.app/ul/v1/swap?buy=&sell={chain}%3A{token}"

def jupiter_swap_link(symbol: str) -> str:
    # Your earlier format: https://jup.ag/swap/FROGE-SOL
    # Only safe when we have a symbol.
    sym = (symbol or "").upper().strip()
    return f"https://jup.ag/swap/{sym}-SOL"

# -----------------------------
# Explorer links
# -----------------------------
def solscan_tx(sig: str) -> str:
    return f"https://solscan.io/tx/{sig}"

def evm_explorer_tx(network: str, tx: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return f"https://basescan.org/tx/{tx}"
    return f"https://etherscan.io/tx/{tx}"

def dex_chain_from_evm_network(network: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return "base"
    return "ethereum"

# -----------------------------
# EVM Security (Alchemy Signature)
# -----------------------------
ALCHEMY_SIGNING_KEY = os.getenv("ALCHEMY_SIGNING_KEY", "").encode()
EVM_WEBHOOK_SECRET = os.getenv("EVM_WEBHOOK_SECRET", "").strip()

def verify_alchemy_signature(raw_body: bytes, sig_header: Optional[str]) -> None:
    """
    Verify X-Alchemy-Signature = HMAC-SHA256(raw_body, ALCHEMY_SIGNING_KEY) hex.
    If ALCHEMY_SIGNING_KEY is not set, do not block (useful for testing).
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
# Behavior / filters
# -----------------------------
IGNORE_TRANSFERS_EVM = os.getenv("IGNORE_TRANSFERS_EVM", "1").strip() not in ("0", "false", "False")
IGNORE_TRANSFERS_SOL = os.getenv("IGNORE_TRANSFERS_SOL", "1").strip() not in ("0", "false", "False")

QUOTE_SYMBOLS_EVM = {s.strip().upper() for s in os.getenv("QUOTE_SYMBOLS_EVM", "ETH,WETH,USDC,USDT,DAI").split(",") if s.strip()}
QUOTE_SYMBOLS_SOL = {s.strip().upper() for s in os.getenv("QUOTE_SYMBOLS_SOL", "SOL,WSOL,USDC,USDT").split(",") if s.strip()}

# Optional minimum filters
MIN_SOL = float(os.getenv("MIN_SOL", "0"))   # ignore tiny SOL transfers when transfers not ignored
MIN_ETH = float(os.getenv("MIN_ETH", "0"))   # ignore tiny ETH transfers when transfers not ignored

# Infra blocklist safety net (EVM): lowercased 0x…
INFRA_BLOCKLIST = {x.lower() for x in parse_csv_set("INFRA_BLOCKLIST")}
if not INFRA_BLOCKLIST:
    INFRA_BLOCKLIST = {
        "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
        "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap SwapRouter02
        "0x66a9893cc07d91d95644aedd05d03f95e1dba8af",  # Uniswap UniversalRouter
        "0x000000000022d473030f116ddee9f6b43ac78ba3",  # Permit2
        "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch Router
        "0x9008d19f58aabd9ed0d60971565aa8510560ab41",  # CoW settlement
    }

# -----------------------------
# EVM parsing (Alchemy Address Activity)
# -----------------------------
def parse_alchemy_address_activity(payload: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Expected:
    { "type":"ADDRESS_ACTIVITY", "event": { "network":"...", "activity":[...] } }
    Returns: (network, activity_list)
    """
    if not isinstance(payload, dict):
        return ("", [])
    if payload.get("type") != "ADDRESS_ACTIVITY":
        return ("", [])
    event = payload.get("event") or {}
    network = event.get("network") or "ETH_MAINNET"
    activity = event.get("activity") or []
    return network, activity if isinstance(activity, list) else []

def group_activity_by_hash(activity: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_hash: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in activity:
        h = a.get("hash")
        if isinstance(h, str) and h.startswith("0x"):
            by_hash[h].append(a)
    return by_hash

def evm_asset_key(a: Dict[str, Any]) -> Tuple[str, str]:
    sym = (a.get("asset") or "UNKNOWN").upper()
    rc = a.get("rawContract") or {}
    addr = (rc.get("address") or "").lower()
    if not addr and sym == "ETH":
        addr = "native"
    if not addr:
        addr = "unknown"
    return addr, sym

def evm_find_tracked_wallet(items: List[Dict[str, Any]]) -> Optional[str]:
    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        if frm and is_tracked_evm(frm):
            return frm
        if to and is_tracked_evm(to):
            return to
    return None

def evm_summarize_for_wallet(items: List[Dict[str, Any]], wallet: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    w = (wallet or "").lower()
    net: Dict[Tuple[str, str], float] = defaultdict(float)

    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        addr, sym = evm_asset_key(a)
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

def evm_classify_side(spent: Optional[Dict[str, Any]], received: Optional[Dict[str, Any]]) -> str:
    if spent and received:
        s_spent = (spent.get("symbol") or "").upper()
        s_recv = (received.get("symbol") or "").upper()
        if s_spent in QUOTE_SYMBOLS_EVM and s_recv not in QUOTE_SYMBOLS_EVM:
            return "BUY"
        if s_recv in QUOTE_SYMBOLS_EVM and s_spent not in QUOTE_SYMBOLS_EVM:
            return "SELL"
        return "SWAP"
    return "TRANSFER"

# -----------------------------
# Solana parsing (Helius Enhanced Webhook)
# -----------------------------
HELIUS_WEBHOOK_SECRET = os.getenv("HELIUS_WEBHOOK_SECRET", "").strip()

def sol_normalize_payload(payload: Any) -> List[Dict[str, Any]]:
    # Helius commonly posts a LIST of tx objects
    if isinstance(payload, list):
        return [p for p in payload if isinstance(p, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []

def sol_find_tracked_wallet(tx: Dict[str, Any]) -> Optional[str]:
    """
    Try common fields:
      - "feePayer"
      - tokenTransfers: fromUserAccount / toUserAccount
      - nativeTransfers: fromUserAccount / toUserAccount
    """
    fee = tx.get("feePayer")
    if isinstance(fee, str) and fee and is_tracked_sol(fee):
        return fee

    for t in tx.get("tokenTransfers", []) or []:
        if not isinstance(t, dict):
            continue
        frm = t.get("fromUserAccount")
        to = t.get("toUserAccount")
        if isinstance(frm, str) and frm and is_tracked_sol(frm):
            return frm
        if isinstance(to, str) and to and is_tracked_sol(to):
            return to

    for n in tx.get("nativeTransfers", []) or []:
        if not isinstance(n, dict):
            continue
        frm = n.get("fromUserAccount")
        to = n.get("toUserAccount")
        if isinstance(frm, str) and frm and is_tracked_sol(frm):
            return frm
        if isinstance(to, str) and to and is_tracked_sol(to):
            return to

    return None

def sol_net_flows(tx: Dict[str, Any], wallet: str) -> Tuple[Dict[str, float], float, Dict[str, str]]:
    """
    Returns:
      token_net_by_mint: mint -> net amount (positive = received)
      sol_net: net SOL (positive = received SOL)
      token_symbol_by_mint: mint -> symbol
    """
    w = wallet
    token_net: Dict[str, float] = defaultdict(float)
    sol_net = 0.0
    sym_by_mint: Dict[str, str] = {}

    for t in tx.get("tokenTransfers", []) or []:
        if not isinstance(t, dict):
            continue
        mint = t.get("mint")
        if not isinstance(mint, str) or not mint:
            continue
        sym = t.get("tokenSymbol") or t.get("symbol") or ""
        if sym:
            sym_by_mint[mint] = str(sym)

        amt = safe_float(t.get("tokenAmount") or t.get("amount") or 0)
        frm = t.get("fromUserAccount")
        to = t.get("toUserAccount")

        if to == w:
            token_net[mint] += amt
        if frm == w:
            token_net[mint] -= amt

    # nativeTransfers values may be in lamports or SOL depending on Helius config;
    # Helius enhanced webhooks typically include "amount" in SOL.
    for n in tx.get("nativeTransfers", []) or []:
        if not isinstance(n, dict):
            continue
        amt = safe_float(n.get("amount") or 0)
        frm = n.get("fromUserAccount")
        to = n.get("toUserAccount")
        if to == w:
            sol_net += amt
        if frm == w:
            sol_net -= amt

    return token_net, sol_net, sym_by_mint

def sol_pick_main_mint(token_net: Dict[str, float]) -> Optional[str]:
    if not token_net:
        return None
    # pick the mint with largest absolute net movement
    return max(token_net.keys(), key=lambda m: abs(token_net[m]))

def sol_classify_side(sol_net: float, token_delta: float) -> str:
    # sol_net negative = spent SOL; token_delta positive = received token => BUY
    if sol_net < 0 and token_delta > 0:
        return "BUY"
    if sol_net > 0 and token_delta < 0:
        return "SELL"
    if token_delta != 0:
        return "SWAP"
    return "TRANSFER"

# -----------------------------
# Summaries
# -----------------------------
alchemy_summary = {
    "received": 0, "sent": 0, "ignored": 0,
    "bad_type": 0, "no_wallet": 0, "untracked": 0,
    "infra_block": 0, "transfer_ignored": 0, "too_small": 0,
    "dedupe": 0, "empty_msg": 0, "exceptions": 0,
    "last_sent_ts": 0,
}

helius_summary = {
    "received": 0, "sent": 0, "ignored": 0,
    "bad_type": 0, "no_wallet": 0, "untracked": 0,
    "transfer_ignored": 0, "too_small": 0,
    "dedupe": 0, "empty_msg": 0, "exceptions": 0,
    "last_sent_ts": 0,
}

def log_summary(tag: str, obj: Dict[str, Any]) -> None:
    log.info("%s_summary=%s", tag, json.dumps(obj, separators=(",", ":")))

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

@app.get("/")
def root():
    return {
        "ok": True,
        "service": "wallet-webhook",
        "routes": ["/helius", "/webhook/evm", "/debug/summary"],
        "watch_sol": len(WATCH_WALLETS_SOL),
        "watch_evm": len(WATCH_WALLETS_EVM),
        "dexscreener": DEXSCREENER_ENABLED,
        "tg_disable_preview": TG_DISABLE_PREVIEW,
    }

@app.get("/health")
def health():
    return {"ok": True, "alchemy_summary": alchemy_summary, "helius_summary": helius_summary}

@app.get("/debug/summary")
def debug_summary():
    return {
        "ok": True,
        "alchemy_summary": alchemy_summary,
        "helius_summary": helius_summary,
        "watch_sol": len(WATCH_WALLETS_SOL),
        "watch_evm": len(WATCH_WALLETS_EVM),
    }

# -----------------------------
# Solana webhook (Helius)  ✅ fixes your /helius 404
# -----------------------------
@app.post("/helius")
async def helius_webhook(
    request: Request,
    authorization: Optional[str] = Header(default=None),
):
    raw = await request.body()
    check_secret(authorization, HELIUS_WEBHOOK_SECRET)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    helius_summary["received"] += 1

    txs = sol_normalize_payload(payload)
    if not txs:
        helius_summary["bad_type"] += 1
        log_summary("helius", helius_summary)
        return {"ok": True, "received": 0, "sent": 0}

    sent = 0
    for tx in txs:
        try:
            sig = tx.get("signature") or tx.get("transactionSignature") or ""
            if not isinstance(sig, str) or not sig:
                helius_summary["bad_type"] += 1
                continue

            tracked = sol_find_tracked_wallet(tx)
            if not tracked:
                helius_summary["no_wallet"] += 1
                continue

            if WATCH_WALLETS_SOL and tracked not in WATCH_WALLETS_SOL:
                helius_summary["untracked"] += 1
                continue

            dedupe_key = f"sol:{tracked}:{sig}"
            if not remember_once(dedupe_key):
                helius_summary["dedupe"] += 1
                helius_summary["ignored"] += 1
                continue

            token_net, sol_net, sym_by_mint = sol_net_flows(tx, tracked)
            main_mint = sol_pick_main_mint(token_net)
            main_delta = token_net.get(main_mint, 0.0) if main_mint else 0.0
            side = sol_classify_side(sol_net, main_delta)

            if IGNORE_TRANSFERS_SOL and side == "TRANSFER":
                helius_summary["transfer_ignored"] += 1
                helius_summary["ignored"] += 1
                continue

            # Optional ignore tiny SOL transfers if transfers are not ignored
            if side == "TRANSFER" and MIN_SOL > 0 and abs(sol_net) < MIN_SOL:
                helius_summary["too_small"] += 1
                helius_summary["ignored"] += 1
                continue

            source = tx.get("source") or "UNKNOWN"
            tx_type = tx.get("type") or "UNKNOWN"
            desc = tx.get("description") or ""

            # Dexscreener enrichment for main token if present
            dex = None
            token_symbol = ""
            if main_mint:
                token_symbol = sym_by_mint.get(main_mint, "")
                dex = dex_enrich("solana", main_mint)

            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡" if side == "SWAP" else "⚪"

            lines = []
            lines.append(f"{emoji} {side} (solana)")
            lines.append(f"Wallet: {label_sol(tracked)}")

            # show spent/received summary (compact)
            if side in ("BUY", "SWAP") and sol_net < 0:
                lines.append(f"Spent: {abs(sol_net):.6g} SOL")
            if side in ("SELL", "SWAP") and sol_net > 0:
                lines.append(f"Received: {abs(sol_net):.6g} SOL")

            if main_mint and main_delta != 0:
                sym = token_symbol or "TOKEN"
                if main_delta > 0:
                    lines.append(f"Received: {abs(main_delta):.6g} {sym} ({main_mint})")
                else:
                    lines.append(f"Spent: {abs(main_delta):.6g} {sym} ({main_mint})")

            lines.append(f"Source: {source}")
            lines.append(f"Type: {tx_type}")

            # Phantom + Jupiter links
            if INCLUDE_PHANTOM_LINKS and main_mint:
                lines.append(f"Phantom token: {phantom_token_link('solana', main_mint)}")
                lines.append(f"Phantom (in-app): {phantom_inapp_token('solana', main_mint)}")
                lines.append(f"Phantom swap: {phantom_swap_link('solana', main_mint)}")

            if INCLUDE_JUPITER_LINKS and main_mint and token_symbol:
                # only when we know the symbol (matches your old message style)
                lines.append(f"Jupiter: {jupiter_swap_link(token_symbol)}")

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

            if desc:
                lines.append(f"Desc: {desc}")

            lines.append(f"Sig: {sig}")
            lines.append(solscan_tx(sig))

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

    # optional shared secret
    check_secret(authorization, EVM_WEBHOOK_SECRET)

    # verify signature
    verify_alchemy_signature(raw, x_alchemy_signature)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    alchemy_summary["received"] += 1

    network, activity = parse_alchemy_address_activity(payload)
    if not activity:
        alchemy_summary["bad_type"] += 1
        log_summary("alchemy", alchemy_summary)
        return {"ok": True, "received": 0, "sent": 0}

    chain = dex_chain_from_evm_network(network)
    by_hash = group_activity_by_hash(activity)

    sent = 0
    for tx_hash, items in by_hash.items():
        try:
            tracked_wallet = evm_find_tracked_wallet(items)
            if not tracked_wallet:
                alchemy_summary["no_wallet"] += 1
                continue

            w = tracked_wallet.lower()

            if WATCH_WALLETS_EVM and w not in WATCH_WALLETS_EVM:
                alchemy_summary["untracked"] += 1
                continue

            # safety net: if you accidentally tracked routers/contracts
            if w in INFRA_BLOCKLIST:
                alchemy_summary["infra_block"] += 1
                alchemy_summary["ignored"] += 1
                continue

            spent, received = evm_summarize_for_wallet(items, w)
            side = evm_classify_side(spent, received)

            if IGNORE_TRANSFERS_EVM and side == "TRANSFER":
                alchemy_summary["transfer_ignored"] += 1
                alchemy_summary["ignored"] += 1
                continue

            # optional ignore tiny ETH transfers if transfers are not ignored
            if side == "TRANSFER" and MIN_ETH > 0 and received:
                if received.get("symbol", "").upper() == "ETH" and received.get("address") == "native":
                    if float(received.get("amount", 0)) < MIN_ETH:
                        alchemy_summary["too_small"] += 1
                        alchemy_summary["ignored"] += 1
                        continue

            dedupe_key = f"evm:{network}:{w}:{tx_hash}:{side}"
            if not remember_once(dedupe_key):
                alchemy_summary["dedupe"] += 1
                alchemy_summary["ignored"] += 1
                continue

            # choose a token to enrich
            token_to_enrich = None
            token_symbol = ""
            if side == "BUY" and received and received.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                token_to_enrich = received.get("address")
                token_symbol = received.get("symbol", "")
            elif side == "SELL" and spent and spent.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                token_to_enrich = spent.get("address")
                token_symbol = spent.get("symbol", "")
            elif side == "SWAP":
                if received and received.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                    token_to_enrich = received.get("address")
                    token_symbol = received.get("symbol", "")
                elif spent and spent.get("symbol", "").upper() not in QUOTE_SYMBOLS_EVM:
                    token_to_enrich = spent.get("address")
                    token_symbol = spent.get("symbol", "")

            dex = dex_enrich(chain, token_to_enrich) if token_to_enrich else None

            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡" if side == "SWAP" else "⚪"
            chain_name = "base" if chain == "base" else "ethereum"

            lines = []
            lines.append(f"{emoji} {side} ({chain_name})")
            lines.append(f"Wallet: {label_evm(w)}")

            if spent:
                lines.append(f"Spent: {spent['amount']:.6g} {spent['symbol']} ({spent['address']})")
            if received:
                lines.append(f"Received: {received['amount']:.6g} {received['symbol']} ({received['address']})")

            # Phantom links for EVM token leg (when we have a token address)
            if INCLUDE_PHANTOM_LINKS and token_to_enrich and token_to_enrich.startswith("0x"):
                lines.append(f"Phantom token: {phantom_token_link(chain_name, token_to_enrich)}")
                lines.append(f"Phantom (in-app): {phantom_inapp_token(chain_name, token_to_enrich)}")
                lines.append(f"Phantom swap: {phantom_swap_link(chain_name, token_to_enrich)}")

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
            lines.append(f"Explorer: {evm_explorer_tx(network, tx_hash)}")

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

# -----------------------------
# Error handler
# -----------------------------
@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})


