# app.py
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
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("wallet-webhook")

# -----------------------------
# ENV helpers
# -----------------------------
def getenv_required(name: str) -> str:
    v = os.getenv(name, "").strip()
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

def parse_wallets(env_name: str) -> set[str]:
    raw = os.getenv(env_name, "")
    return set(w for w in raw.replace(" ", "").split(",") if w)

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = getenv_required("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = int(getenv_required("TELEGRAM_CHAT_ID"))

TG_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
tg = requests.Session()

def tg_send(text: str, silent: bool = False) -> None:
    r = tg.post(
        f"{TG_BASE}/sendMessage",
        json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "disable_notification": bool(silent),
            "disable_web_page_preview": True,
        },
        timeout=20,
    )
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data)

# -----------------------------
# Watchlists
# -----------------------------
WATCH_WALLETS_SOL = parse_wallets("WATCH_WALLETS_SOL")                 # base58
WATCH_WALLETS_EVM = {w.lower() for w in parse_wallets("WATCH_WALLETS_EVM")}  # 0x...

# If you forgot to set WATCH_WALLETS_*, don't block everything (your requested behavior)
def is_tracked_evm(wallet: str) -> bool:
    wallet = (wallet or "").lower()
    return (not WATCH_WALLETS_EVM) or (wallet in WATCH_WALLETS_EVM)

# -----------------------------
# Optional header secret checks
# (Helius commonly uses Authorization header via authHeader;
#  Alchemy uses signature verification instead, but you can also set a secret if you want.)
# -----------------------------
SOLANA_WEBHOOK_SECRET = os.getenv("SOLANA_WEBHOOK_SECRET", os.getenv("WEBHOOK_SECRET", "")).strip()
EVM_WEBHOOK_SECRET = os.getenv("EVM_WEBHOOK_SECRET", "").strip()

def check_secret(auth_header: Optional[str], expected: str) -> None:
    if not expected:
        return
    if not auth_header or auth_header.strip() != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")

# -----------------------------
# Alchemy signature verification (NEW)
# -----------------------------
ALCHEMY_SIGNING_KEY = os.getenv("ALCHEMY_SIGNING_KEY", "").encode()

def verify_alchemy_signature(raw_body: bytes, sig_header: Optional[str]) -> None:
    """
    Alchemy sends X-Alchemy-Signature. You verify HMAC-SHA256 of the raw body using your signing key.
    If ALCHEMY_SIGNING_KEY is not set, we won't block (good for initial testing).
    """
    if not ALCHEMY_SIGNING_KEY:
        return

    if not sig_header:
        raise HTTPException(status_code=401, detail="Missing X-Alchemy-Signature")

    sig = sig_header.strip()
    if sig.startswith("sha256="):
        sig = sig.split("=", 1)[1].strip()

    expected = hmac.new(ALCHEMY_SIGNING_KEY, raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")

# -----------------------------
# Dedupe (prevents double alerts)
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
# Explorer links
# -----------------------------
def evm_explorer_tx(network: str, tx: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return f"https://basescan.org/tx/{tx}"
    return f"https://etherscan.io/tx/{tx}"

# -----------------------------
# Parsing: Alchemy Address Activity
# -----------------------------
QUOTE_SYMBOLS = {s.strip().upper() for s in os.getenv("QUOTE_SYMBOLS_EVM", "ETH,WETH,USDC,USDT,DAI").split(",") if s.strip()}

def parse_alchemy_address_activity(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Expects: { "type":"ADDRESS_ACTIVITY", "event": { "network":"...", "activity":[...] } }
    Returns a list of raw activity items.
    """
    if not isinstance(payload, dict):
        return []
    if payload.get("type") != "ADDRESS_ACTIVITY":
        return []
    event = payload.get("event") or {}
    activity = event.get("activity") or []
    if not isinstance(activity, list):
        return []
    return activity

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
    raw = a.get("rawContract") or {}
    addr = (raw.get("address") or "").lower()
    if not addr and sym == "ETH":
        addr = "native"
    if not addr:
        addr = "unknown"
    return addr, sym

def summarize_for_wallet(items: List[Dict[str, Any]], wallet: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Compute net flows for the tracked wallet:
      incoming = positive, outgoing = negative
    Returns (spent, received) as dicts: {address,symbol,amount}
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

def find_tracked_wallet(items: List[Dict[str, Any]]) -> Optional[str]:
    """
    Pick the watched wallet involved in this tx (either fromAddress or toAddress).
    """
    for a in items:
        frm = (a.get("fromAddress") or "").lower()
        to = (a.get("toAddress") or "").lower()
        if frm and is_tracked_evm(frm):
            return frm
        if to and is_tracked_evm(to):
            return to
    return None

# -----------------------------
# App + summaries
# -----------------------------
app = FastAPI()

summary = {
    "received": 0,
    "sent": 0,
    "ignored": 0,
    "bad_type": 0,
    "dedupe": 0,
    "no_wallet": 0,
    "untracked": 0,
    "empty_msg": 0,
    "exceptions": 0,
    "last_sent_ts": 0,
}

def log_summary(tag: str):
    log.info("%s_summary=%s", tag, json.dumps(summary, separators=(",", ":")))

@app.get("/")
def root():
    return {"ok": True, "service": "wallet-webhook", "watch_evm": len(WATCH_WALLETS_EVM), "watch_sol": len(WATCH_WALLETS_SOL)}

@app.get("/health")
def health():
    return {"ok": True, "summary": summary, "watch_evm": len(WATCH_WALLETS_EVM), "watch_sol": len(WATCH_WALLETS_SOL)}

# -----------------------------
# EVM webhook (Alchemy) with signature verification ✅
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

    # NEW: verify Alchemy signature
    verify_alchemy_signature(raw, x_alchemy_signature)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    summary["received"] += 1

    event = payload.get("event") or {}
    network = event.get("network") or "ETH_MAINNET"

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

            # if WATCH_WALLETS_EVM is set, make sure it's in the set
            if WATCH_WALLETS_EVM and tracked_wallet.lower() not in WATCH_WALLETS_EVM:
                summary["untracked"] += 1
                continue

            spent, received = summarize_for_wallet(items, tracked_wallet)
            side = classify_side(spent, received)

            dedupe_key = f"{network}:{tracked_wallet}:{tx_hash}:{side}"
            if not remember_once(dedupe_key):
                summary["dedupe"] += 1
                continue

            # Build message
            lines = []
            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡" if side == "SWAP" else "⚪"
            chain_name = "base" if "BASE" in (network or "").upper() else "ethereum"
            lines.append(f"{emoji} {side} ({chain_name})")
            lines.append(f"Wallet: {tracked_wallet}")
            if spent:
                lines.append(f"Spent: {spent['amount']:.6g} {spent['symbol']} ({spent['address']})")
            if received:
                lines.append(f"Received: {received['amount']:.6g} {received['symbol']} ({received['address']})")
            lines.append(f"Tx: {tx_hash}")
            lines.append(f"Explorer: {evm_explorer_tx(network, tx_hash)}")

            msg = "\n".join(lines).strip()
            if not msg:
                summary["empty_msg"] += 1
                continue

            tg_send(msg)
            sent += 1
            summary["sent"] += 1
            summary["last_sent_ts"] = int(time.time())

        except Exception as e:
            summary["exceptions"] += 1
            log.exception("evm processing error: %s", e)

    if sent == 0:
        summary["ignored"] += 1

    log_summary("alchemy")
    return {"ok": True, "received": len(by_hash), "sent": sent}

# -----------------------------
# (Optional) Solana webhook placeholder
# Keep if you still use Helius; otherwise you can delete this endpoint.
# -----------------------------
@app.post("/webhook/solana")
async def webhook_solana(request: Request, authorization: Optional[str] = Header(default=None)):
    check_secret(authorization, SOLANA_WEBHOOK_SECRET)
    # Keep your existing Helius parsing here if you use it.
    return {"ok": True, "note": "solana endpoint present (parsing not included in this rewrite)"}

@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})
