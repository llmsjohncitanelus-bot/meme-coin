# app.py
import os
import time
import json
import logging
import threading
from queue import SimpleQueue, Empty
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# -----------------------------
# LOGGING
# -----------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("wallet-webhook")

# -----------------------------
# ENV
# -----------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# If set, requests must include this exact value in the Authorization header
HELIUS_AUTH_HEADER = os.getenv("HELIUS_AUTH_HEADER", "").strip()

# Throttle Telegram sends (seconds)
TG_MSG_INTERVAL = float(os.getenv("TG_MSG_INTERVAL", "0.75"))

# Only send alerts for these tx types
# (Helius uses types like BUY/SELL/SWAP/TRANSFER/NFT_SALE/etc.)  :contentReference[oaicite:2]{index=2}
ALLOWED_TYPES = set(
    t for t in os.getenv("ALLOWED_TYPES", "BUY,SELL,SWAP").replace(" ", "").split(",") if t
)

# Optional: if you want ONLY buy/sell semantics, keep SWAP allowed but we’ll label it BUY/SELL when we can.
CLASSIFY_SWAPS = os.getenv("CLASSIFY_SWAPS", "1").strip() not in ("0", "false", "False")

# ---- Your requested snippet (included verbatim) ----
WATCH_WALLETS = set(
    w for w in os.getenv("WATCH_WALLETS", "").replace(" ", "").split(",") if w
)

def is_tracked(wallet: str) -> bool:
    # If you forgot to set WATCH_WALLETS, don't block everything
    return (not WATCH_WALLETS) or (wallet in WATCH_WALLETS)
# ----------------------------------------------------

# Known “quote” mints for simple buy/sell classification
WSOL_MINT = "So11111111111111111111111111111111111111112"  # Wrapped SOL :contentReference[oaicite:3]{index=3}
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # USDC :contentReference[oaicite:4]{index=4}
# (You can add USDT here if you want, but not required.)
QUOTE_MINTS = {WSOL_MINT, USDC_MINT}

# -----------------------------
# TELEGRAM SENDER (queued)
# -----------------------------
TG_QUEUE: "SimpleQueue[str]" = SimpleQueue()
_session = requests.Session()

def telegram_send(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram not configured (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID).")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": True}
    r = _session.post(url, json=payload, timeout=20)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API error: {data}")

def tg_worker():
    last = 0.0
    while True:
        try:
            msg = TG_QUEUE.get()
        except Exception:
            time.sleep(0.1)
            continue

        # throttle
        now = time.time()
        sleep_for = (last + TG_MSG_INTERVAL) - now
        if sleep_for > 0:
            time.sleep(sleep_for)

        try:
            telegram_send(msg)
        except Exception as e:
            log.exception("Telegram send failed: %s", e)

        last = time.time()

# -----------------------------
# DEDUPE (Helius may retry)
# -----------------------------
SEEN_MAX = int(os.getenv("SEEN_MAX", "5000"))
_seen_deque = deque(maxlen=SEEN_MAX)
_seen_set: Set[str] = set()

def seen(signature: str) -> bool:
    if not signature:
        return False
    if signature in _seen_set:
        return True
    _seen_deque.append(signature)
    _seen_set.add(signature)
    if len(_seen_deque) == _seen_deque.maxlen:
        # rebuild set occasionally to match deque contents
        _seen_set.clear()
        _seen_set.update(_seen_deque)
    return False

# -----------------------------
# PARSING HELPERS
# -----------------------------
def short_addr(a: str, n: int = 6) -> str:
    if not a or len(a) <= (n * 2 + 3):
        return a
    return f"{a[:n]}...{a[-n:]}"

def extract_wallets(tx: Dict[str, Any]) -> Set[str]:
    wallets: Set[str] = set()

    fee_payer = tx.get("feePayer")
    if isinstance(fee_payer, str):
        wallets.add(fee_payer)

    for ad in tx.get("accountData", []) or []:
        acct = ad.get("account")
        if isinstance(acct, str):
            wallets.add(acct)

    for nt in tx.get("nativeTransfers", []) or []:
        a = nt.get("fromUserAccount")
        b = nt.get("toUserAccount")
        if isinstance(a, str): wallets.add(a)
        if isinstance(b, str): wallets.add(b)

    for tt in tx.get("tokenTransfers", []) or []:
        a = tt.get("fromUserAccount")
        b = tt.get("toUserAccount")
        if isinstance(a, str): wallets.add(a)
        if isinstance(b, str): wallets.add(b)

    # Swap event wallets (if present)
    ev = tx.get("events") or {}
    swap = ev.get("swap") if isinstance(ev, dict) else None
    if isinstance(swap, dict):
        inner = swap.get("innerSwaps") or []
        for ins in inner:
            for ti in ins.get("tokenInputs", []) or []:
                a = ti.get("fromUserAccount")
                b = ti.get("toUserAccount")
                if isinstance(a, str): wallets.add(a)
                if isinstance(b, str): wallets.add(b)
            for to in ins.get("tokenOutputs", []) or []:
                a = to.get("fromUserAccount")
                b = to.get("toUserAccount")
                if isinstance(a, str): wallets.add(a)
                if isinstance(b, str): wallets.add(b)

    return wallets

def tracked_wallet_in_tx(tx: Dict[str, Any]) -> Optional[str]:
    wallets = extract_wallets(tx)
    # If WATCH_WALLETS is empty, just pick the feePayer (or any wallet) so we don't block everything.
    if not WATCH_WALLETS:
        fp = tx.get("feePayer")
        if isinstance(fp, str):
            return fp
        return next(iter(wallets), None)

    for w in wallets:
        if w in WATCH_WALLETS:
            return w
    return None

def aggregate_swap_flows_for_wallet(tx: Dict[str, Any], wallet: str) -> Tuple[Dict[str, float], Dict[str, float]]:
    """
    Returns:
      spent_by_mint: mint -> tokenAmount (spent by wallet)
      recv_by_mint: mint -> tokenAmount (received by wallet)
    Uses events.swap.innerSwaps.tokenInputs/tokenOutputs when available. :contentReference[oaicite:5]{index=5}
    """
    spent: Dict[str, float] = {}
    recv: Dict[str, float] = {}

    ev = tx.get("events") or {}
    swap = ev.get("swap") if isinstance(ev, dict) else None
    if not isinstance(swap, dict):
        return spent, recv

    inner = swap.get("innerSwaps") or []
    for ins in inner:
        for ti in ins.get("tokenInputs", []) or []:
            if ti.get("fromUserAccount") == wallet:
                mint = ti.get("mint") or "unknown"
                amt = float(ti.get("tokenAmount") or 0)
                spent[mint] = spent.get(mint, 0.0) + amt

        for to in ins.get("tokenOutputs", []) or []:
            if to.get("toUserAccount") == wallet:
                mint = to.get("mint") or "unknown"
                amt = float(to.get("tokenAmount") or 0)
                recv[mint] = recv.get(mint, 0.0) + amt

    return spent, recv

def pick_top_flow(flow: Dict[str, float]) -> Tuple[str, float]:
    if not flow:
        return ("", 0.0)
    mint, amt = max(flow.items(), key=lambda kv: kv[1])
    return mint, amt

def classify_buy_sell_swap(tx: Dict[str, Any], wallet: str) -> Tuple[str, str]:
    """
    Returns (side, summary_line)
    side: BUY / SELL / SWAP (best-effort)
    """
    tx_type = (tx.get("type") or "").upper()
    sig = tx.get("signature") or ""
    desc = tx.get("description") or ""

    # If Helius already labeled it BUY/SELL (pump-amm), respect that. :contentReference[oaicite:6]{index=6}
    if tx_type in ("BUY", "SELL"):
        return tx_type, desc

    # Otherwise try to classify SWAP using swap flows
    spent, recv = aggregate_swap_flows_for_wallet(tx, wallet)
    spent_mint, spent_amt = pick_top_flow(spent)
    recv_mint, recv_amt = pick_top_flow(recv)

    if not spent_mint and not recv_mint:
        return "SWAP", desc or f"Sig: {short_addr(sig)}"

    # Heuristic: quote -> other = BUY; other -> quote = SELL
    if spent_mint in QUOTE_MINTS and recv_mint and recv_mint not in QUOTE_MINTS:
        side = "BUY"
    elif recv_mint in QUOTE_MINTS and spent_mint and spent_mint not in QUOTE_MINTS:
        side = "SELL"
    else:
        side = "SWAP"

    summary = f"Spent {spent_amt:g} {short_addr(spent_mint)} | Received {recv_amt:g} {short_addr(recv_mint)}"
    return side, summary

def build_message(tx: Dict[str, Any], wallet: str) -> str:
    sig = tx.get("signature") or ""
    ts = tx.get("timestamp")
    tx_type = (tx.get("type") or "").upper()
    source = tx.get("source") or ""
    desc = tx.get("description") or ""

    # Buy/sell label
    side, summary = classify_buy_sell_swap(tx, wallet)
    if not CLASSIFY_SWAPS and tx_type == "SWAP":
        side = "SWAP"

    # Only alert BUY/SELL (and optionally SWAP if included in ALLOWED_TYPES)
    # We still label SWAP as BUY/SELL when we can, but keep filtering based on original type.
    # If you want to filter on side instead, change the logic in the webhook handler.
    label = "🟢 BUY" if side == "BUY" else ("🔴 SELL" if side == "SELL" else "🔁 SWAP")

    lines = [
        f"{label}  WALLET TRADE",
        f"Wallet: {wallet}",
    ]
    if summary:
        lines.append(summary)
    if desc and desc != summary:
        lines.append(f"Desc: {desc}")
    if source:
        lines.append(f"Source: {source}")
    if ts:
        lines.append(f"Timestamp: {ts}")
    if sig:
        lines.append(f"Sig: {sig}")
        lines.append(f"https://solscan.io/tx/{sig}")

    return "\n".join(lines)

# -----------------------------
# FASTAPI APP
# -----------------------------
app = FastAPI()

@app.on_event("startup")
def _startup():
    threading.Thread(target=tg_worker, daemon=True).start()

    # Startup ping so you know env loaded
    TG_QUEUE.put(
        "✅ Service started.\n"
        f"WATCH_WALLETS: {len(WATCH_WALLETS)} loaded\n"
        f"ALLOWED_TYPES: {','.join(sorted(ALLOWED_TYPES))}\n"
        f"TG_MSG_INTERVAL: {TG_MSG_INTERVAL:.2f}s"
    )

@app.get("/")
def root():
    return {"ok": True, "service": "wallet-webhook", "mode": "buy/sell"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/helius")
async def helius_webhook(request: Request):
    # Auth (only enforce if env var is set)
    if HELIUS_AUTH_HEADER:
        got = request.headers.get("authorization", "")
        if got != HELIUS_AUTH_HEADER:
            raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Helius enhanced webhooks send an array/list of enhanced tx objects. :contentReference[oaicite:7]{index=7}
    txs: List[Dict[str, Any]]
    if isinstance(body, list):
        txs = body
    elif isinstance(body, dict) and isinstance(body.get("transactions"), list):
        txs = body["transactions"]
    else:
        raise HTTPException(status_code=400, detail="Expected a JSON array (list) of transactions")

    sent = 0
    ignored = 0

    for tx in txs:
        if not isinstance(tx, dict):
            ignored += 1
            continue

        sig = tx.get("signature") or ""
        if sig and seen(sig):
            ignored += 1
            continue

        tx_type = (tx.get("type") or "").upper()

        # Filter to buy/sell/swap only
        if tx_type and tx_type not in ALLOWED_TYPES:
            ignored += 1
            continue

        wallet = tracked_wallet_in_tx(tx)
        if not wallet or not is_tracked(wallet):
            ignored += 1
            continue

        # If tx is SWAP but we couldn't classify it, it may still be useful; we keep it.
        msg = build_message(tx, wallet)

        # If the result label is SWAP and you want ONLY BUY/SELL messages, uncomment:
        # if msg.startswith("🔁 SWAP"):
        #     ignored += 1
        #     continue

        TG_QUEUE.put(msg)
        sent += 1

    return JSONResponse({"ok": True, "received": len(txs), "sent": sent, "ignored": ignored})
