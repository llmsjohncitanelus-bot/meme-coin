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
# LOGGING
# ============================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)
log = logging.getLogger("wallet-webhook")

# ============================================================
# ENV
# ============================================================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
HELIUS_AUTH_HEADER = os.getenv("HELIUS_AUTH_HEADER", "").strip()

# If empty, allow ALL tx types (recommended to avoid missing trades)
ALLOWED_TYPES = set(
    t for t in os.getenv("ALLOWED_TYPES", "").replace(" ", "").split(",") if t
)

CLASSIFY_SWAPS = os.getenv("CLASSIFY_SWAPS", "1").strip().lower() not in ("0", "false", "no")

TG_MSG_INTERVAL = float(os.getenv("TG_MSG_INTERVAL", "0.75"))

# ---- Your requested snippet ----
WATCH_WALLETS = set(
    w for w in os.getenv("WATCH_WALLETS", "").replace(" ", "").split(",") if w
)

def is_tracked(wallet: str) -> bool:
    # If you forgot to set WATCH_WALLETS, don't block everything
    return (not WATCH_WALLETS) or (wallet in WATCH_WALLETS)

# ============================================================
# HOLD MODE (30–60 min)
# ============================================================
HOLD_MODE = os.getenv("HOLD_MODE", "1").strip().lower() not in ("0", "false", "no")
HOLD_MINUTES = int(os.getenv("HOLD_MINUTES", "60"))
HOLD_UPDATE_MINUTES = int(os.getenv("HOLD_UPDATE_MINUTES", "10"))
HOLD_POLL_SECONDS = int(os.getenv("HOLD_POLL_SECONDS", "60"))

HOLD_TRAIL_STOP_PCT = float(os.getenv("HOLD_TRAIL_STOP_PCT", "0.18"))
HOLD_LIQ_DROP_PCT = float(os.getenv("HOLD_LIQ_DROP_PCT", "0.25"))

HOLD_MAX_WATCHES = int(os.getenv("HOLD_MAX_WATCHES", "100"))

# ============================================================
# SOLANA QUOTE MINTS (for BUY/SELL classification)
# ============================================================
WSOL_MINT = "So11111111111111111111111111111111111111112"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
QUOTE_MINTS = {WSOL_MINT, USDC_MINT}

# ============================================================
# DEXSCREENER
# ============================================================
ENABLE_DEXSCREENER = os.getenv("ENABLE_DEXSCREENER", "1").strip().lower() not in ("0", "false", "no")
DEX_CHAIN = os.getenv("DEXSCREENER_CHAIN", "solana").strip() or "solana"
DEX_TIMEOUT = float(os.getenv("DEX_TIMEOUT", "10"))
DEX_CACHE_TTL = int(os.getenv("DEX_CACHE_TTL", "60"))  # keep fresh for holds
DEX_MIN_LIQ_USD = float(os.getenv("DEX_MIN_LIQ_USD", "2000"))

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
# TELEGRAM QUEUE
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
        "disable_web_page_preview": False,
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

def now_ts() -> float:
    return time.time()

# ============================================================
# DEXSCREENER HELPERS
# ============================================================
def _liq_usd(pair: Dict[str, Any]) -> float:
    liq = pair.get("liquidity") or {}
    try:
        return float(liq.get("usd") or 0.0)
    except Exception:
        return 0.0

def dexscreener_best_pair(mint: str, force: bool = False) -> Optional[Dict[str, Any]]:
    if not ENABLE_DEXSCREENER or not mint:
        return None

    now = now_ts()
    hit = _dex_cache.get(mint)
    if (not force) and hit and hit[0] > now:
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

def dex_url_from_pair(pair: Optional[Dict[str, Any]]) -> str:
    if not pair:
        return ""
    url = pair.get("url") or ""
    if url:
        return url
    pair_addr = pair.get("pairAddress") or pair.get("pairId") or ""
    return f"https://dexscreener.com/{DEX_CHAIN}/{pair_addr}" if pair_addr else ""

def dex_metrics(pair: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not pair:
        return {
            "price": None, "liq": None, "vol5": None, "vol1h": None, "chg5": None,
            "txns5": None, "url": ""
        }
    price = _to_float(pair.get("priceUsd"))
    liq = _to_float((pair.get("liquidity") or {}).get("usd"))
    vol5 = _to_float((pair.get("volume") or {}).get("m5"))
    vol1h = _to_float((pair.get("volume") or {}).get("h1"))
    chg5 = _to_float((pair.get("priceChange") or {}).get("m5"))
    txns5 = (pair.get("txns") or {}).get("m5") or {}
    buys = int(txns5.get("buys") or 0)
    sells = int(txns5.get("sells") or 0)
    return {
        "price": price,
        "liq": liq,
        "vol5": vol5,
        "vol1h": vol1h,
        "chg5": chg5,
        "txns5": buys + sells,
        "url": dex_url_from_pair(pair),
    }

# ============================================================
# WALLET + SWAP FLOW PARSING
# ============================================================
def extract_wallets(tx: Dict[str, Any]) -> Set[str]:
    wallets: Set[str] = set()

    fp = tx.get("feePayer")
    if isinstance(fp, str):
        wallets.add(fp)

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

def aggregate_token_transfer_deltas(tx: Dict[str, Any], wallet: str) -> Dict[str, float]:
    """
    Fallback when events.swap is missing.
    Computes net token delta per mint for this wallet using tokenTransfers.
    """
    delta: Dict[str, float] = {}
    for tt in (tx.get("tokenTransfers") or []):
        if not isinstance(tt, dict):
            continue
        mint = tt.get("mint") or ""
        amt = float(tt.get("tokenAmount") or 0)
        frm = tt.get("fromUserAccount")
        to = tt.get("toUserAccount")
        # wallet receives
        if to == wallet and mint:
            delta[mint] = delta.get(mint, 0.0) + amt
        # wallet sends
        if frm == wallet and mint:
            delta[mint] = delta.get(mint, 0.0) - amt
    return delta

def pick_top_flow(flow: Dict[str, float]) -> Tuple[str, float]:
    if not flow:
        return ("", 0.0)
    mint, amt = max(flow.items(), key=lambda kv: kv[1])
    return mint, amt

def pick_top_abs(delta: Dict[str, float], sign: int) -> Tuple[str, float]:
    # sign: +1 for received (positive), -1 for spent (negative)
    items = [(m, v) for m, v in delta.items() if (v > 0 if sign > 0 else v < 0)]
    if not items:
        return ("", 0.0)
    m, v = max(items, key=lambda kv: abs(kv[1]))
    return m, abs(v)

def detect_meme_mint(spent_mint: str, recv_mint: str) -> str:
    if spent_mint in QUOTE_MINTS and recv_mint and recv_mint not in QUOTE_MINTS:
        return recv_mint
    if recv_mint in QUOTE_MINTS and spent_mint and spent_mint not in QUOTE_MINTS:
        return spent_mint
    if recv_mint and recv_mint not in QUOTE_MINTS:
        return recv_mint
    return ""

def classify_buy_sell(tx: Dict[str, Any], wallet: str) -> Tuple[str, str, str]:
    """
    Returns (side, summary, meme_mint)
    side: BUY or SELL if classified, else "" (ignored)
    """
    tx_type = (tx.get("type") or "").upper()
    desc = tx.get("description") or ""
    sig = tx.get("signature") or ""

    # 1) Prefer events.swap
    spent, recv = aggregate_swap_flows_for_wallet(tx, wallet)
    if spent or recv:
        sm, sa = pick_top_flow(spent)
        rm, ra = pick_top_flow(recv)

        meme = detect_meme_mint(sm, rm)
        side = ""
        if sm in QUOTE_MINTS and rm and rm not in QUOTE_MINTS:
            side = "BUY"
        elif rm in QUOTE_MINTS and sm and sm not in QUOTE_MINTS:
            side = "SELL"

        summary = f"Spent {sa:g} {short_addr(sm)} | Received {ra:g} {short_addr(rm)}" if sm and rm else (desc or "")
        return side, summary, meme

    # 2) Fallback: tokenTransfers net deltas
    delta = aggregate_token_transfer_deltas(tx, wallet)
    if delta:
        spent_mint, spent_amt = pick_top_abs(delta, -1)
        recv_mint, recv_amt = pick_top_abs(delta, +1)
        meme = detect_meme_mint(spent_mint, recv_mint)

        side = ""
        if spent_mint in QUOTE_MINTS and recv_mint and recv_mint not in QUOTE_MINTS:
            side = "BUY"
        elif recv_mint in QUOTE_MINTS and spent_mint and spent_mint not in QUOTE_MINTS:
            side = "SELL"

        summary = ""
        if spent_mint and recv_mint:
            summary = f"Spent {spent_amt:g} {short_addr(spent_mint)} | Received {recv_amt:g} {short_addr(recv_mint)}"
        else:
            summary = desc or f"Sig: {short_addr(sig)}"
        return side, summary, meme

    # If we can't classify -> ignore
    return "", (desc or f"Sig: {short_addr(sig)}"), ""

# ============================================================
# HOLD WATCH STATE
# ============================================================
WATCH_LOCK = threading.Lock()
hold_watches: Dict[str, Dict[str, Any]] = {}

def watch_id(wallet: str, mint: str) -> str:
    return f"{wallet}:{mint}"

def start_hold_watch(wallet: str, mint: str, entry_price: float, dex_url: str, entry_sig: str):
    if not HOLD_MODE:
        return
    if not mint or not entry_price:
        return

    wid = watch_id(wallet, mint)
    now = now_ts()

    with WATCH_LOCK:
        # cap total watches
        if len(hold_watches) >= HOLD_MAX_WATCHES:
            # drop the oldest by started_at
            oldest = min(hold_watches.items(), key=lambda kv: kv[1].get("started_at", now))[0]
            hold_watches.pop(oldest, None)

        hold_watches[wid] = {
            "wallet": wallet,
            "mint": mint,
            "entry_price": entry_price,
            "peak_price": entry_price,
            "last_price": entry_price,
            "dex_url": dex_url,
            "entry_sig": entry_sig,
            "started_at": now,
            "expires_at": now + HOLD_MINUTES * 60,
            "next_update_at": now + HOLD_UPDATE_MINUTES * 60,
            "entry_liq": None,  # set on first refresh if available
        }

def end_hold_watch(wid: str):
    with WATCH_LOCK:
        hold_watches.pop(wid, None)

def pct(a: float, b: float) -> float:
    if a <= 0:
        return 0.0
    return ((b / a) - 1.0) * 100.0

def hold_worker():
    while True:
        try:
            now = now_ts()
            to_end: List[str] = []
            updates: List[Tuple[str, str]] = []

            with WATCH_LOCK:
                items = list(hold_watches.items())

            for wid, w in items:
                if now >= w["expires_at"]:
                    # time stop
                    updates.append((wid, "⏱️ HOLD END (time stop reached)"))
                    to_end.append(wid)
                    continue

                # refresh dexscreener
                pair = dexscreener_best_pair(w["mint"], force=True)
                m = dex_metrics(pair)
                price = m["price"]
                liq = m["liq"]

                if price is None:
                    # can't update; skip
                    continue

                w["last_price"] = price
                if price > w["peak_price"]:
                    w["peak_price"] = price

                if w["entry_liq"] is None and liq is not None:
                    w["entry_liq"] = liq

                # trailing stop
                trail_floor = w["peak_price"] * (1.0 - HOLD_TRAIL_STOP_PCT)
                if price <= trail_floor:
                    updates.append((wid, f"🟠 HOLD EXIT SIGNAL (trail stop {int(HOLD_TRAIL_STOP_PCT*100)}% hit)"))
                    to_end.append(wid)
                    continue

                # liquidity drop warning/exit
                if w["entry_liq"] is not None and liq is not None and w["entry_liq"] > 0:
                    if liq <= w["entry_liq"] * (1.0 - HOLD_LIQ_DROP_PCT):
                        updates.append((wid, f"🟠 HOLD EXIT SIGNAL (liquidity dropped {int(HOLD_LIQ_DROP_PCT*100)}%+)"))
                        to_end.append(wid)
                        continue

                # periodic update
                if now >= w["next_update_at"]:
                    updates.append((wid, "📈 HOLD UPDATE"))
                    w["next_update_at"] = now + HOLD_UPDATE_MINUTES * 60

                # write back updated watch
                with WATCH_LOCK:
                    if wid in hold_watches:
                        hold_watches[wid].update(w)

            # send updates
            for wid, headline in updates:
                with WATCH_LOCK:
                    w = hold_watches.get(wid)
                if not w:
                    continue

                pair = dexscreener_best_pair(w["mint"], force=True)
                m = dex_metrics(pair)
                cur = m["price"] or w["last_price"]
                entry = w["entry_price"]
                peak = w["peak_price"]

                mins_in = int((now_ts() - w["started_at"]) / 60)
                pnl = pct(entry, cur)
                peak_pnl = pct(entry, peak)

                msg = (
                    f"{headline}\n"
                    f"Wallet: {w['wallet']}\n"
                    f"Mint: {w['mint']}\n"
                    f"Minutes in: {mins_in}m / {HOLD_MINUTES}m\n"
                    f"Entry: ${entry:,.8f}\n"
                    f"Now:   ${cur:,.8f}  ({pnl:+.1f}%)\n"
                    f"Peak:  ${peak:,.8f} ({peak_pnl:+.1f}%)\n"
                )
                if m["liq"] is not None:
                    msg += f"Liquidity: ${m['liq']:,.0f}\n"
                if m["vol5"] is not None or m["vol1h"] is not None:
                    v5 = f"${m['vol5']:,.0f}" if m["vol5"] is not None else "?"
                    v1 = f"${m['vol1h']:,.0f}" if m["vol1h"] is not None else "?"
                    msg += f"Vol(5m): {v5} | Vol(1h): {v1}\n"
                if m["url"]:
                    msg += f"Dexscreener: {m['url']}\n"

                TG_QUEUE.put(msg)

            for wid in to_end:
                end_hold_watch(wid)

        except Exception as e:
            log.exception("hold_worker error: %s", e)

        time.sleep(HOLD_POLL_SECONDS)

# ============================================================
# MESSAGE BUILDER (BUY/SELL alerts)
# ============================================================
def build_trade_message(tx: Dict[str, Any], wallet: str) -> Tuple[str, Optional[str], Optional[float], str]:
    """
    Returns:
      text, meme_mint, entry_price, dex_url
    """
    sig = tx.get("signature") or ""
    desc = tx.get("description") or ""
    source = tx.get("source") or ""
    tx_type = (tx.get("type") or "").upper()

    side, summary, meme_mint = classify_buy_sell(tx, wallet)
    if side not in ("BUY", "SELL"):
        return "", None, None, ""

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

    entry_price = None
    dex_url = ""
    if ENABLE_DEXSCREENER and meme_mint:
        try:
            pair = dexscreener_best_pair(meme_mint, force=True)
            m = dex_metrics(pair)
            dex_url = m["url"]
            if dex_url:
                lines.append(f"Dexscreener: {dex_url}")
            if m["price"] is not None and m["liq"] is not None:
                lines.append(f"Price: ${m['price']:,.8f} | Liquidity: ${m['liq']:,.0f}")
                entry_price = m["price"]
            if m["vol5"] is not None or m["vol1h"] is not None:
                v5 = f"${m['vol5']:,.0f}" if m["vol5"] is not None else "?"
                v1 = f"${m['vol1h']:,.0f}" if m["vol1h"] is not None else "?"
                lines.append(f"Vol(5m) {v5} | Vol(1h) {v1}")
            if meme_mint:
                lines.append(f"Mint: {meme_mint}")
        except Exception:
            lines.append("Dexscreener: (lookup failed)")
            if meme_mint:
                lines.append(f"Mint: {meme_mint}")

    if sig:
        lines.append(f"Sig: {sig}")
        lines.append(f"https://solscan.io/tx/{sig}")

    return "\n".join(lines), meme_mint, entry_price, dex_url

# ============================================================
# FASTAPI
# ============================================================
app = FastAPI()

@app.on_event("startup")
def _startup():
    threading.Thread(target=tg_worker, daemon=True).start()
    if HOLD_MODE:
        threading.Thread(target=hold_worker, daemon=True).start()

    TG_QUEUE.put(
        "✅ Service started (BUY/SELL alerts + Hold Watch mode).\n"
        f"WATCH_WALLETS: {len(WATCH_WALLETS)} loaded\n"
        f"ALLOWED_TYPES: {('ALL' if not ALLOWED_TYPES else ','.join(sorted(ALLOWED_TYPES)))}\n"
        f"CLASSIFY_SWAPS: {CLASSIFY_SWAPS}\n"
        f"HOLD_MODE: {HOLD_MODE} ({HOLD_MINUTES}m, updates every {HOLD_UPDATE_MINUTES}m)\n"
        f"DEX_CACHE_TTL: {DEX_CACHE_TTL}s\n"
        f"TG_MSG_INTERVAL: {TG_MSG_INTERVAL:.2f}s"
    )

@app.get("/")
def root():
    return {"ok": True, "service": "wallet-webhook", "mode": "buy/sell + hold_watch"}

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/favicon.ico")
def favicon():
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

    if isinstance(body, list):
        txs = body
    elif isinstance(body, dict) and isinstance(body.get("transactions"), list):
        txs = body["transactions"]
    else:
        raise HTTPException(status_code=400, detail="Expected a JSON array (list) of transactions")

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
        "hold_started": 0,
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

            # If ALLOWED_TYPES is empty -> allow all
            if ALLOWED_TYPES and tx_type and tx_type not in ALLOWED_TYPES:
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

            msg, meme_mint, entry_price, dex_url = build_trade_message(tx, wallet)
            if not msg:
                reasons["ignored"] += 1
                reasons["empty_msg"] += 1
                continue

            TG_QUEUE.put(msg)
            reasons["sent"] += 1

            # Start 30–60 min hold watch only on BUY
            if HOLD_MODE and msg.startswith("🟢 BUY") and meme_mint and entry_price:
                start_hold_watch(wallet, meme_mint, entry_price, dex_url, sig)
                reasons["hold_started"] += 1

        except Exception:
            reasons["ignored"] += 1
            reasons["exceptions"] += 1

    log.info("helius_summary=%s", json.dumps(reasons, separators=(",", ":")))
    return JSONResponse({"ok": True, **reasons})

