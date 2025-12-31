# app.py
import os
import time
import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Set, Optional

from fastapi import FastAPI, Request, HTTPException
from telegram_alerts import TelegramAlerter

# ============================================================
# ENV / CONFIG
# ============================================================

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID_RAW = os.getenv("TELEGRAM_CHAT_ID", "").strip()
HELIUS_AUTH_HEADER = os.getenv("HELIUS_AUTH_HEADER", "").strip()

# Telegram pacing (1 msg/sec default)
TG_MSG_INTERVAL = float(os.getenv("TG_MSG_INTERVAL", "1.0").strip() or "1.0")

# Safety: cap extremely long messages
MAX_MSG_CHARS = int(os.getenv("MAX_MSG_CHARS", "3500").strip() or "3500")

# If WATCH_WALLETS is empty, we still alert (Helius already filtered)
# If WATCH_WALLETS is set, we try to show only tracked wallets in message.
# ============================================================
# YOUR REQUESTED SNIPPET
# ============================================================
WATCH_WALLETS = set(
    w for w in os.getenv("WATCH_WALLETS", "").replace(" ", "").split(",") if w
)

def is_tracked(wallet: str) -> bool:
    # If you forgot to set WATCH_WALLETS, don't block everything
    return (not WATCH_WALLETS) or (wallet in WATCH_WALLETS)

# ============================================================
# VALIDATION
# ============================================================

if not BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN in Railway Variables.")
if not CHAT_ID_RAW:
    raise RuntimeError("Missing TELEGRAM_CHAT_ID in Railway Variables.")
try:
    CHAT_ID = int(CHAT_ID_RAW)
except ValueError as e:
    raise RuntimeError("TELEGRAM_CHAT_ID must be an integer.") from e

alerter = TelegramAlerter(bot_token=BOT_TOKEN, chat_id=CHAT_ID)

# Telegram send queue so webhook handler stays fast
tx_alert_q: asyncio.Queue[str] = asyncio.Queue(maxsize=5000)

# ============================================================
# HELPERS
# ============================================================

def _normalize_auth_header(value: str) -> str:
    v = (value or "").strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    return v

def _truncate(s: str, n: int) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"

def _short_sig(sig: str) -> str:
    if not sig:
        return "?"
    sig = str(sig)
    if len(sig) <= 18:
        return sig
    return sig[:10] + "…" + sig[-6:]

def _as_list_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []

def _add_if_wallet(found: Set[str], v: Any):
    if isinstance(v, str) and len(v) >= 25:
        if is_tracked(v):
            found.add(v)

def extract_wallets_best_effort(tx: Dict[str, Any]) -> List[str]:
    """
    Best-effort extraction of involved wallets from common Enhanced payload fields.
    NOTE: Even if this fails, we still send the message because Helius already filtered
    to your accountAddresses.
    """
    found: Set[str] = set()

    # Fee payer / payer keys that sometimes appear
    for k in ("feePayer", "feePayerAccount", "payer", "source", "account"):
        _add_if_wallet(found, tx.get(k))

    # Native transfers
    for t in (tx.get("nativeTransfers") or []):
        if isinstance(t, dict):
            _add_if_wallet(found, t.get("fromUserAccount"))
            _add_if_wallet(found, t.get("toUserAccount"))

    # Token transfers
    for t in (tx.get("tokenTransfers") or []):
        if isinstance(t, dict):
            _add_if_wallet(found, t.get("fromUserAccount"))
            _add_if_wallet(found, t.get("toUserAccount"))
            _add_if_wallet(found, t.get("userAccount"))

    # Events → swap → innerSwaps
    events = tx.get("events") or {}
    if isinstance(events, dict):
        swap = events.get("swap") or {}
        if isinstance(swap, dict):
            inner_swaps = swap.get("innerSwaps") or []
            for inner in inner_swaps:
                if not isinstance(inner, dict):
                    continue
                for ti in (inner.get("tokenInputs") or []):
                    if isinstance(ti, dict):
                        _add_if_wallet(found, ti.get("fromUserAccount"))
                for to in (inner.get("tokenOutputs") or []):
                    if isinstance(to, dict):
                        _add_if_wallet(found, to.get("toUserAccount"))

    # If WATCH_WALLETS is set, found already filtered by is_tracked().
    # If WATCH_WALLETS is empty, is_tracked() returns True and we keep anything we spot.
    return sorted(found)

def summarize_tx(tx: Dict[str, Any]) -> str:
    sig = tx.get("signature") or ""
    ttype = tx.get("type") or tx.get("transactionType") or "UNKNOWN"
    ts = tx.get("timestamp") or tx.get("time") or ""

    desc = (tx.get("description") or "").strip()
    desc = _truncate(desc, 500)

    wallets = extract_wallets_best_effort(tx)
    wallet_line = ", ".join(wallets[:5]) + ("…" if len(wallets) > 5 else "")
    if not wallet_line:
        wallet_line = "(wallet not parsed)"

    # Counts
    token_transfers = tx.get("tokenTransfers") or []
    native_transfers = tx.get("nativeTransfers") or []
    tt_n = len(token_transfers) if isinstance(token_transfers, list) else 0
    nt_n = len(native_transfers) if isinstance(native_transfers, list) else 0

    # Quick swap hint
    swap_hint = ""
    events = tx.get("events") or {}
    if isinstance(events, dict) and isinstance(events.get("swap"), dict):
        swap_hint = " | swap ✅"

    link = f"https://solscan.io/tx/{sig}" if sig else ""

    lines = [
        "📣 WALLET TX",
        f"Type: {ttype}{swap_hint}",
        f"Wallet(s): {wallet_line}",
        f"Sig: {_short_sig(sig)}",
        f"Transfers: token={tt_n} native={nt_n}",
    ]

    if ts:
        lines.append(f"Timestamp: {ts}")

    if desc:
        lines.append(f"Desc: {desc}")

    if link:
        lines.append(link)

    msg = "\n".join(lines)
    return _truncate(msg, MAX_MSG_CHARS)

async def tg_send(text: str, silent: bool = False):
    # TelegramAlerter.send is sync; run it off the event loop
    await asyncio.to_thread(alerter.send, text, silent)

async def telegram_sender_loop():
    """
    Sends queued messages at a controlled pace so we don't
    slow down webhook responses or get Telegram rate-limited.
    """
    while True:
        msg = await tx_alert_q.get()
        try:
            await tg_send(msg, silent=False)
        except Exception:
            # Don't crash the loop; just drop and continue
            pass
        await asyncio.sleep(TG_MSG_INTERVAL)

# ============================================================
# FASTAPI APP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    sender_task = asyncio.create_task(telegram_sender_loop())
    # Startup ping (silent)
    try:
        wallets_count = len(WATCH_WALLETS)
        await tg_send(
            f"✅ Service started. High-volume wallet TX alerts ON.\n"
            f"WATCH_WALLETS: {wallets_count} loaded\n"
            f"TG_MSG_INTERVAL: {TG_MSG_INTERVAL}s",
            silent=True,
        )
    except Exception:
        pass

    try:
        yield
    finally:
        sender_task.cancel()

app = FastAPI(lifespan=lifespan)

@app.get("/health")
def health():
    return {"ok": True}

# Optional root handlers to reduce 404 spam in logs
@app.get("/")
def root_get():
    return {"ok": True}

@app.post("/")
def root_post():
    return {"ok": True}

@app.post("/helius")
async def helius_webhook(request: Request):
    # Verify authHeader -> Authorization echo
    if HELIUS_AUTH_HEADER:
        got = _normalize_auth_header(request.headers.get("Authorization", ""))
        if got != HELIUS_AUTH_HEADER:
            raise HTTPException(status_code=401, detail="Unauthorized")

    payload = await request.json()
    txs = _as_list_payload(payload)

    # Enqueue one Telegram message per tx (high volume)
    for tx in txs:
        msg = summarize_tx(tx)

        # If WATCH_WALLETS is set but we couldn't parse wallets, still send
        # because Helius already filtered to your accountAddresses.
        try:
            tx_alert_q.put_nowait(msg)
        except asyncio.QueueFull:
            # If overwhelmed, drop newest
            pass

    # Return quickly
    return {"ok": True, "txs": len(txs)}
