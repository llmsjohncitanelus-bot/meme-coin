# app.py
import os
import time
import json
import logging
import threading
from queue import SimpleQueue
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response

# ============================================================
# CONFIG / ENV
# ============================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)
log = logging.getLogger("wallet-webhook")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# This must match what you set in Helius "authHeader" / "Authorization header"
HELIUS_AUTH_HEADER = os.getenv("HELIUS_AUTH_HEADER", "").strip()

# BUY/SELL mode: you almost always want SWAP allowed (then we classify SWAP as BUY or SELL)
ALLOWED_TYPES = set(
    t for t in os.getenv("ALLOWED_TYPES", "BUY,SELL,SWAP").replace(" ", "").split(",") if t
)
CLASSIFY_SWAPS = os.getenv("CLASSIFY_SWAPS", "1").strip().lower() not in ("0", "false", "no")

# Throttle Telegram sends (seconds)
TG_MSG_INTERVAL = float(os.getenv("TG_MSG_INTERVAL", "0.75"))

# ---- Your requested snippet (verbatim) ----
WATCH_WALLETS = set(
    w for w in os.getenv("WATCH_WALLETS", "").replace(" ", "").split(",") if w
)

def is_tracked(wallet: str) -> bool:
    # If you forgot to set WATCH_WALLETS, don't block everything
    return (not WATCH_WALLETS) or (wallet in WATCH_WALLETS)

# ============================================================
# SOLANA "QUOTE" MINTS (for buy/sell classification)
# ============================================================
WSOL_MINT = "So11111111111111111111111111111111111111112"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
QUOTE_MINTS = {WSOL_MINT, USDC_MINT}

# ============================================================
# OPTIONAL: DEXSCREENER ENRICHMENT (price/liquidity)
# ============================================================
ENABLE_DEXSCREENER = os.getenv("ENABLE_DEXSCREENER", "1").strip().lower() not in ("0", "false", "no")
DEX_CHAIN = os.getenv("DEXSCREENER_CHAIN", "solana").strip() or "solana"
DEX_TIMEOUT = float(os.getenv("DEX_TIMEOUT", "10"))
DEX_CACHE_TTL = int(os.getenv("DEX_CACHE_TTL", "900"))          # 15 min
DEX_MIN_LIQ_USD = float(os.getenv("DEX_MIN_LIQ_USD", "3000"))   # ignore dust pools

_dex_cache: Dict[str, Tuple[float, Optional[Dict[str, Any]]]] = {}

# ============================================================
# HTTP SESSIONS (retries)
# ============================================================
def make_retrying_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

tg_http = make_retrying_session()
dex_http = make_retrying_session()

# ============================================================
# TELEGRAM QUEUE SENDER
# ============================================================
TG_QUEUE: "SimpleQueue[str]" = SimpleQueue()

def telegram_send(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram not configured (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID).")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": False,  # show Dexscreener preview
    }
    r = tg_http.post(url, json=payload, timeout=20)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API error: {data}")

def tg_worker():
    last = 0.0
    while True:
        msg = TG_QUEUE.get()
        now = time.time()
        wait = (last + TG_MSG_INTERVAL) - now
        if wait > 0:
            time.sleep(wait)
        try:
            telegram_send(msg)
        except Exception as e:
            log.exception("Telegram send failed: %s", e)
        last = time.time()

# ============================================================
# DEDUPE (Helius retries)
# ============================================================
SEEN_MAX = int(os.getenv("SEEN_MAX", "6000"))
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
        _seen_set.clear()
        _seen_set.update(_seen_deque)
    return False

# ============================================================
# UTILS
# ============================================================
def short_addr(a: str, n: int = 6) -> str:
    if not a or len(a) <= (n * 2 + 3):
        return a
    return f"{a[:n]}...{a[-n:]}"

def _to_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None

# ============================================================
# DEXSCREENER HELPERS
# ============================================================
def _liq_usd(pair: Dict[str, Any]) -> float:
    liq = pair.get("liquidity") or {}
    try:
        return float(liq.get("usd") or 0.0)
    except Exception:
        return 0.0

def dexscreener_best_pair(mint: str) -> Optional[Dict[str, Any]]:
    if not ENABLE_DEXSCREENER or not mint:
        return None

    now = time.time()
    hit = _dex_cache.get(mint)
    if hit and hit[0] > now:
        return hit[1]

    url = f"https://api.dexscreener.com/token-pairs/v1/{DEX_CHAIN}/{mint}"
    r = dex_http.get(url, timeout=DEX_TIMEOUT)
    r.raise_for_status()
    data = r.json()

    best = None
    if isinstance(data, list) and data:
        candidate = max(data, key=_liq_usd)
        if _liq_usd(candidate) >= DEX_MIN_LIQ_USD:
            best = candidate

    _dex_cache[mint] = (now + DEX_CACHE_TTL, best)
    return best

def format_dex_block(pair: Optional[Dict[str, Any]]) -> str:
    if not ENABLE_DEXSCREENER:
        return ""

    if not pair:
        return "Dexscreener: (no liquid pool found)"

    url = pair.get("url")
    if not url:
        pair_addr = pair.get("pairAddress") or pair.get("pairId") or ""
        url = f"https://dexscreener.com/{DEX_CHAIN}/{pair_addr}" if pair_addr else ""

    price = _to_float(pair.get("priceUsd"))
    liq = _to_float((pair.get("liquidity") or {}).get("usd"))
    vol5 = _to_float((pair.get("volume") or {}).get("m5"))
    vol1h = _to_float((pair.get("volume") or {}).get("h1"))
    chg5 = _to_float((pair.get("priceChange") or {}).get("m5"))

    lines = []
    if url:
        lines.append(f"Dexscreener: {url}")
    if price is not None or liq is not None:
        p_txt = f"${price:,.8f}" if price is not None else "?"
        l_txt = f"${liq:,.0f}" if liq is not None else "?"
        lines.append(f"Price: {p_txt} | Liquidity: {l_txt}")

    extras = []
    if vol5 is not None:
        extras.append(f"Vol(5m) ${vol5:,.0f}")
    if vol1h is not None:
        extras.append(f"Vol(1h) ${vol1h:,.0f}")
    if chg5 is not None:
        extras.append(f"Δ5m {chg5:.1f}%")
    if extras:
        lines.append(" | ".join(extras))

    return "\n".join(lines)

# ============================================================
# WALLET + SWAP FLOW PARSING (best-effort)
# ============================================================
def extract_wallets(tx: Dict[str, Any]) -> Set[str]:
    wallets: Set[str] = set()

    fp = tx.get("feePayer")
    if isinstance(fp, str):
        wallets.add(fp)

    # accountData sometimes includes accounts touched
    for ad in (tx.get("accountData") or []):
        if isinstance(ad, dict):
            acct = ad.get("account")
            if isinstance(acct, str):
                wallets.add(acct)

    for nt in (tx.get("nativeTransfers") or []):
        if isinstance(nt, dict):
            a = nt.get("fromUserAccount")
            b = nt.get("toUserAccount")
            if isinstance(a, str): wallets.add(a)
            if isinstance(b, str): wallets.add(b)

    for tt in (tx.get("tokenTransfers") or []):
        if isinstance(tt, dict):
            a = tt.get("fromUserAccount")
            b = tt.get("toUserAccount")
            u = tt.get("userAccount")
            if isinstance(a, str): wallets.add(a)
            if isinstance(b, str): wallets.add(b)
            if isinstance(u, str): wallets.add(u)

    ev = tx.get("events") or {}
    swap = ev.get("swap") if isinstance(ev, dict) else None
    if isinstance(swap, dict):
        for ins in (swap.get("innerSwaps") or []):
            for ti in (ins.get("tokenInputs") or []):
                if isinstance(ti, dict):
                    a = ti.get("fromUserAccount")
                    b = ti.get("toUserAccount")
                    if isinstance(a, str): wallets.add(a)
                    if isinstance(b, str): wallets.add(b)
            for to in (ins.get("tokenOutputs") or []):
                if isinstance(to, dict):
                    a = to.get("fromUserAccount")
                    b = to.get("toUserAccount")
                    if isinstance(a, str): wallets.add(a)
                    if isinstance(b, str): wallets.add(b)

    return wallets

def tracked_wallet_in_tx(tx: Dict[str, Any]) -> Optional[str]:
    wallets = extract_wallets(tx)

    # If WATCH_WALLETS is empty, pick feePayer (or any) so we don't block everything
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
    spent: Dict[str, float] = {}
    recv: Dict[str, float] = {}

    ev = tx.get("events") or {}
    swap = ev.get("swap") if isinstance(ev, dict) else None
    if not isinstance(swap, dict):
        return spent, recv

    for ins in (swap.get("innerSwaps") or []):
        for ti in (ins.get("tokenInputs") or []):
            if isinstance(ti, dict) and ti.get("fromUserAccount") == wallet:
                mint = ti.get("mint") or "unknown"
                amt = float(ti.get("tokenAmount") or 0)
                spent[mint] = spent.get(mint, 0.0) + amt

        for to in (ins.get("tokenOutputs") or []):
            if isinstance(to, dict) and to.get("toUserAccount") == wallet:
                mint = to.get("mint") or "unknown"
                amt = float(to.get("tokenAmount") or 0)
                recv[mint] = recv.get(mint, 0.0) + amt

    return spent, recv

def pick_top_flow(flow: Dict[str, float]) -> Tuple[str, float]:
    if not flow:
        return ("", 0.0)
    mint, amt = max(flow.items(), key=lambda kv: kv[1])
    return mint, amt

def detect_meme_mint(spent_mint: str, recv_mint: str) -> str:
    # BUY: spent quote -> received meme
    if spent_mint in QUOTE_MINTS and recv_mint and recv_mint not in QUOTE_MINTS:
        return recv_mint
    # SELL: received quote -> spent meme
    if recv_mint in QUOTE_MINTS and spent_mint and spent_mint not in QUOTE_MINTS:
        return spent_mint
    # fallback: if we got a non-quote output mint, prefer that
    if recv_mint and recv_mint not in QUOTE_MINTS:
        return recv_mint
    return ""

def classify_buy_sell_swap(tx: Dict[str, Any], wallet: str) -> Tuple[str, str, str]:
    """
    Returns (side, summary, meme_mint)
    side: BUY/SELL if possible, otherwise SWAP.
    """
    tx_type = (tx.get("type") or "").upper()
    desc = tx.get("description") or ""
    sig = tx.get("signature") or ""

    # Respect explicit BUY/SELL labels
    if tx_type in ("BUY", "SELL"):
        spent, recv = aggregate_swap_flows_for_wallet(tx, wallet)
        sm, sa = pick_top_flow(spent)
        rm, ra = pick_top_flow(recv)
        meme = detect_meme_mint(sm, rm)
        return tx_type, (desc or f"Sig: {short_addr(sig)}"), meme

    # Otherwise, try to classify SWAP into BUY/SELL using quote flow
    spent, recv = aggregate_swap_flows_for_wallet(tx, wallet)
    sm, sa = pick_top_flow(spent)
    rm, ra = pick_top_flow(recv)
    meme = detect_meme_mint(sm, rm)

    if sm and rm:
        if sm in QUOTE_MINTS and rm not in QUOTE_MINTS:
            side = "BUY"
        elif rm in QUOTE_MINTS and sm not in QUOTE_MINTS:
            side = "SELL"
        else:
            side = "SWAP"
        summary = f"Spent {sa:g} {short_addr(sm)} | Received {ra:g} {short_addr(rm)}"
        return side, summary, meme

    return "SWAP", (desc or f"Sig: {short_addr(sig)}"), meme

def build_message(tx: Dict[str, Any], wallet: str) -> str:
    sig = tx.get("signature") or ""
    desc = tx.get("description") or ""
    source = tx.get("source") or ""
    tx_type = (tx.get("type") or "").upper()

    side, summary, meme_mint = classify_buy_sell_swap(tx, wallet)

    # ✅ NEW LOGIC (buy/sell only, but allow SWAPs that we classified into BUY/SELL)
    # If classification failed, side will remain SWAP -> we drop it.
    if side not in ("BUY", "SELL"):
        return ""

    label = "🟢 BUY" if side == "BUY" else "🔴 SELL"
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
    if tx_type:
        lines.append(f"Type: {tx_type}")

    # Dexscreener enrichment + price/liquidity
    if ENABLE_DEXSCREENER and meme_mint:
        try:
            best = dexscreener_best_pair(meme_mint)
            block = format_dex_block(best)
            if block:
                lines.append(block)
            lines.append(f"Mint: {meme_mint}")
        except Exception:
            lines.append("Dexscreener: (lookup failed)")
            lines.append(f"Mint: {meme_mint}")

    if sig:
        lines.append(f"Sig: {sig}")
        lines.append(f"https://solscan.io/tx/{sig}")

    return "\n".join(lines)

# ============================================================
# FASTAPI APP
# ============================================================
app = FastAPI()

@app.on_event("startup")
def _startup():
    threading.Thread(target=tg_worker, daemon=True).start()
    TG_QUEUE.put(
        "✅ Service started (BUY/SELL mode + why-ignored counters).\n"
        f"WATCH_WALLETS: {len(WATCH_WALLETS)} loaded\n"
        f"ALLOWED_TYPES: {','.join(sorted(ALLOWED_TYPES))}\n"
        f"CLASSIFY_SWAPS: {CLASSIFY_SWAPS}\n"
        f"ENABLE_DEXSCREENER: {ENABLE_DEXSCREENER}\n"
        f"TG_MSG_INTERVAL: {TG_MSG_INTERVAL:.2f}s"
    )

@app.get("/")
def root():
    return {"ok": True, "service": "wallet-webhook", "mode": "buy/sell"}

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/favicon.ico")
def favicon():
    # Stop noisy 404s in logs
    return Response(status_code=204)

@app.post("/helius")
async def helius_webhook(request: Request):
    # Auth check (only enforce if env var is set)
    if HELIUS_AUTH_HEADER:
        got = request.headers.get("authorization", "")
        if got != HELIUS_AUTH_HEADER:
            raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Expect list of enhanced tx objects
    if isinstance(body, list):
        txs = body
    elif isinstance(body, dict) and isinstance(body.get("transactions"), list):
        txs = body["transactions"]
    else:
        raise HTTPException(status_code=400, detail="Expected a JSON array (list) of transactions")

    # ✅ WHY-IGNORED counters
    reasons = {
        "received": len(txs),
        "sent": 0,
        "ignored": 0,
        "bad_type": 0,
        "dedupe": 0,
        "no_wallet": 0,
        "untracked": 0,
        "empty_msg": 0,
        "exceptions": 0,
    }

    for tx in txs:
        try:
            if not isinstance(tx, dict):
                reasons["ignored"] += 1
                reasons["exceptions"] += 1
                continue

            sig = tx.get("signature") or ""
            if sig and seen(sig):
                reasons["ignored"] += 1
                reasons["dedupe"] += 1
                continue

            tx_type = (tx.get("type") or "").upper()

            # IMPORTANT: keep SWAP allowed or you'll rarely see anything
            if tx_type and tx_type not in ALLOWED_TYPES:
                reasons["ignored"] += 1
                reasons["bad_type"] += 1
                continue

            wallet = tracked_wallet_in_tx(tx)
            if not wallet:
                reasons["ignored"] += 1
                reasons["no_wallet"] += 1
                continue

            if not is_tracked(wallet):
                reasons["ignored"] += 1
                reasons["untracked"] += 1
                continue

            msg = build_message(tx, wallet)
            if not msg:
                reasons["ignored"] += 1
                reasons["empty_msg"] += 1
                continue

            TG_QUEUE.put(msg)
            reasons["sent"] += 1

        except Exception:
            reasons["ignored"] += 1
            reasons["exceptions"] += 1

    # Log summary for Railway Log Explorer
    log.info("helius_summary=%s", json.dumps(reasons, separators=(",", ":")))

    # Also return it so you can see it directly in Railway HTTP logs
    return JSONResponse({"ok": True, **reasons})

