# app.py
import os
import time
import json
import asyncio
import random
from typing import Any, Dict, List, Optional
from collections import defaultdict, deque
from contextlib import asynccontextmanager

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from fastapi import FastAPI, Request, HTTPException

from telegram_alerts import TelegramAlerter
from scoring import compute_scores

# -----------------------------
# CONFIG
# -----------------------------
CHAIN = "solana"
POLL_SECONDS = 15

# Entry gates (tune later)
MIN_SAFETY = 15
MIN_MOMENTUM = 48

MIN_LIQ_USD = 1500
MIN_TXNS_5M = 18
MIN_VOL5_USD = 650

MIN_BUY_RATIO = 0.45
MAX_BUY_RATIO = 0.95
MAX_CHG5M_FOR_ENTRY = 300

# Preset A holds (30–90m-ish)
MIN_HOLD_SECONDS = 20 * 60
TRAIL_STOP_PCT = 0.35
TIME_STOP_SECONDS = 60 * 60
LIQ_DROP_PCT = 0.20

COOLDOWN_SECONDS = 120
REQUEST_TIMEOUT = 45

# Debug sampling
DEBUG_REJECTIONS = True
DEBUG_SAMPLE_RATE = 0.02

# Ignore common “spent” mints
IGNORE_MINTS = {
    "So11111111111111111111111111111111111111112",  # wSOL
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",  # USDT
}

# Put your 10 wallets here
WATCH_WALLETS = {
    # "WALLET1",
    # "WALLET2",
}

TOKEN_PAIRS_URL = "https://api.dexscreener.com/token-pairs/v1/{chain}/{token}"

STATE_FILE = "state.json"  # best effort; may reset on redeploy

# -----------------------------
# ENV / TELEGRAM / AUTH
# -----------------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
HELIUS_AUTH_HEADER = os.getenv("HELIUS_AUTH_HEADER", "").strip()

if not BOT_TOKEN or not CHAT_ID:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in Railway Variables.")

alerter = TelegramAlerter(bot_token=BOT_TOKEN, chat_id=int(CHAT_ID))

# -----------------------------
# REQUESTS SESSION WITH RETRIES
# -----------------------------
session = requests.Session()
retries = Retry(
    total=5,
    connect=5,
    read=5,
    backoff_factor=1.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    raise_on_status=False,
)
adapter = HTTPAdapter(max_retries=retries)
session.mount("https://", adapter)
session.mount("http://", adapter)

# -----------------------------
# RUNTIME STATE
# -----------------------------
candidates_q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=5000)

alerted_mints = set()                   # mints already entry-alerted
cooldown_until: Dict[str, float] = {}   # mint -> ts
watch: Dict[str, Dict[str, Any]] = {}   # mint -> peak, last_high_ts, started_ts
history = defaultdict(lambda: deque(maxlen=10))

state_lock = asyncio.Lock()


# -----------------------------
# UTIL
# -----------------------------
def safe_get(d, *path, default=0):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur if cur is not None else default


def snapshot_from_pair(pair: Dict[str, Any], ts: float) -> Dict[str, Any]:
    price = float(pair.get("priceUsd") or 0) or 0.0
    liq = float(safe_get(pair, "liquidity", "usd", default=0) or 0)
    vol5 = float(safe_get(pair, "volume", "m5", default=0) or 0)
    buys = int(safe_get(pair, "txns", "m5", "buys", default=0) or 0)
    sells = int(safe_get(pair, "txns", "m5", "sells", default=0) or 0)
    txns = buys + sells
    chg5 = float(safe_get(pair, "priceChange", "m5", default=0) or 0)
    buy_ratio = (buys / txns) if txns > 0 else 0.0
    return {"ts": ts, "price": price, "liq": liq, "vol5": vol5, "buys": buys, "sells": sells,
            "txns": txns, "chg5": chg5, "buy_ratio": buy_ratio}


def pick_best_pair(pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    def liq_usd(p: Dict[str, Any]) -> float:
        return float((p.get("liquidity") or {}).get("usd") or 0)
    return max(pairs, key=liq_usd)


def liquidity_drop(hist: deque, drop_pct: float) -> bool:
    if len(hist) < 2:
        return False
    a, b = list(hist)[-2], list(hist)[-1]
    if a["liq"] <= 0:
        return False
    return (b["liq"] / a["liq"]) < (1 - drop_pct)


def trailing_stop_trigger(peak: float, current: float, stop_pct: float) -> bool:
    return peak > 0 and current <= peak * (1 - stop_pct)


def fmt_entry(mint: str, pair: Dict[str, Any], safety: int, momentum: int, s: Dict[str, Any], source: str) -> str:
    base = pair.get("baseToken") or {}
    name = base.get("name") or "Unknown"
    symbol = base.get("symbol") or ""
    pair_url = pair.get("url") or ""
    return (
        f"🟢 ENTRY WATCH (Preset A)\n"
        f"{name} ({symbol})\n"
        f"Source: {source}\n"
        f"Safety: {safety}/100 | Momentum: {momentum}/100\n"
        f"Price: {s['price']:.8f}\n"
        f"Liq: ${s['liq']:,.0f} | Txns(5m): {s['txns']} (B{s['buys']}/S{s['sells']})\n"
        f"Vol(5m): ${s['vol5']:,.0f} | BuyRatio: {s['buy_ratio']:.2f} | Δ5m: {s['chg5']}%\n"
        f"Mint: {mint}\n"
        f"Pair: {pair_url}"
    )


def fmt_exit(reason: str, mint: str, pair: Dict[str, Any], s: Dict[str, Any], extra: str = "") -> str:
    base = pair.get("baseToken") or {}
    name = base.get("name") or "Unknown"
    symbol = base.get("symbol") or ""
    pair_url = pair.get("url") or ""
    msg = (
        f"🔴 EXIT ALERT ({reason})\n"
        f"{name} ({symbol})\n"
        f"Price: {s['price']:.8f}\n"
        f"Liq: ${s['liq']:,.0f} | Txns(5m): {s['txns']} (B{s['buys']}/S{s['sells']})\n"
        f"Vol(5m): ${s['vol5']:,.0f} | BuyRatio: {s['buy_ratio']:.2f} | Δ5m: {s['chg5']}%\n"
        f"Mint: {mint}\n"
        f"Pair: {pair_url}"
    )
    return msg + (("\n" + extra) if extra else "")


def maybe_debug(text: str):
    if not DEBUG_REJECTIONS:
        return
    if random.random() >= DEBUG_SAMPLE_RATE:
        return
    # silent so it doesn’t spam you
    try:
        alerter.send(f"🔎 reject: {text}", silent=True)
    except Exception:
        pass


def get_pairs_sync(chain: str, mint: str) -> List[Dict[str, Any]]:
    url = TOKEN_PAIRS_URL.format(chain=chain, token=mint)
    r = session.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()


async def tg_send(text: str, silent: bool = False):
    await asyncio.to_thread(alerter.send, text, silent)


# -----------------------------
# STATE PERSIST (best effort)
# -----------------------------
def load_state():
    global alerted_mints, cooldown_until, watch
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        alerted_mints = set(data.get("alerted_mints", []))
        cooldown_until = {k: float(v) for k, v in (data.get("cooldown_until", {}) or {}).items()}
        watch = data.get("watch", {}) or {}
    except FileNotFoundError:
        pass
    except Exception:
        pass


def save_state():
    data = {
        "alerted_mints": list(alerted_mints)[-50000:],
        "cooldown_until": cooldown_until,
        "watch": watch,
        "updated_at": time.time(),
    }
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


# -----------------------------
# BACKGROUND LOOPS
# -----------------------------
async def candidate_loop():
    while True:
        ev = await candidates_q.get()
        mint = ev.get("mint")
        if not mint:
            continue

        now = time.time()

        async with state_lock:
            if mint in alerted_mints or mint in watch:
                continue
            if now < float(cooldown_until.get(mint, 0)):
                continue

        try:
            pairs = await asyncio.to_thread(get_pairs_sync, CHAIN, mint)
            if not pairs:
                maybe_debug(f"{mint} no pairs yet")
                async with state_lock:
                    cooldown_until[mint] = now + COOLDOWN_SECONDS
                continue

            best = pick_best_pair(pairs)
            s = snapshot_from_pair(best, time.time())
            history[mint].append(s)

            # floors
            if s["liq"] < MIN_LIQ_USD or s["txns"] < MIN_TXNS_5M or s["vol5"] < MIN_VOL5_USD:
                maybe_debug(f"{mint} floors liq={s['liq']:.0f} txns={s['txns']} vol5={s['vol5']:.0f}")
                async with state_lock:
                    cooldown_until[mint] = now + COOLDOWN_SECONDS
                continue

            if not (MIN_BUY_RATIO <= s["buy_ratio"] <= MAX_BUY_RATIO):
                maybe_debug(f"{mint} buy_ratio {s['buy_ratio']:.2f} out of range")
                async with state_lock:
                    cooldown_until[mint] = now + COOLDOWN_SECONDS
                continue

            if s["chg5"] > MAX_CHG5M_FOR_ENTRY:
                maybe_debug(f"{mint} chg5 {s['chg5']:.1f}% too hot")
                async with state_lock:
                    cooldown_until[mint] = now + COOLDOWN_SECONDS
                continue

            safety, momentum, _ = compute_scores(best)
            if safety < MIN_SAFETY or momentum < MIN_MOMENTUM:
                maybe_debug(f"{mint} score S{safety}/{MIN_SAFETY} M{momentum}/{MIN_MOMENTUM}")
                async with state_lock:
                    cooldown_until[mint] = now + COOLDOWN_SECONDS
                continue

            source = f"wallet {ev.get('wallet','?')} (sig {str(ev.get('signature',''))[:8]}…)"
            await tg_send(fmt_entry(mint, best, safety, momentum, s, source), silent=False)

            async with state_lock:
                alerted_mints.add(mint)
                watch[mint] = {"peak": s["price"], "last_high_ts": s["ts"], "started_ts": s["ts"]}
                cooldown_until.pop(mint, None)
                save_state()

        except Exception as e:
            maybe_debug(f"{mint} candidate error: {e}")
            async with state_lock:
                cooldown_until[mint] = now + COOLDOWN_SECONDS


async def watch_loop():
    while True:
        await asyncio.sleep(POLL_SECONDS)
        now = time.time()

        async with state_lock:
            mints = list(watch.keys())

        for mint in mints:
            try:
                pairs = await asyncio.to_thread(get_pairs_sync, CHAIN, mint)
                if not pairs:
                    continue
                best = pick_best_pair(pairs)
                s = snapshot_from_pair(best, time.time())
                history[mint].append(s)

                async with state_lock:
                    w = watch.get(mint)
                    if not w:
                        continue

                    if s["price"] > w["peak"]:
                        w["peak"] = s["price"]
                        w["last_high_ts"] = s["ts"]

                    held_for = s["ts"] - w["started_ts"]

                    # immediate exits
                    if liquidity_drop(history[mint], LIQ_DROP_PCT):
                        await tg_send(fmt_exit("LIQUIDITY DROP", mint, best, s))
                        watch.pop(mint, None)
                        save_state()
                        continue

                    if held_for < MIN_HOLD_SECONDS:
                        continue

                    if trailing_stop_trigger(w["peak"], s["price"], TRAIL_STOP_PCT):
                        extra = f"Peak: {w['peak']:.8f} | Trail: {int(TRAIL_STOP_PCT*100)}% | Held: {int(held_for/60)}m"
                        await tg_send(fmt_exit("TRAIL STOP", mint, best, s, extra=extra))
                        watch.pop(mint, None)
                        save_state()
                        continue

                    if (s["ts"] - w["last_high_ts"]) >= TIME_STOP_SECONDS:
                        extra = f"No new highs for {int(TIME_STOP_SECONDS/60)}m | Held: {int(held_for/60)}m"
                        await tg_send(fmt_exit("TIME STOP", mint, best, s, extra=extra))
                        watch.pop(mint, None)
                        save_state()
                        continue

            except Exception:
                continue


# -----------------------------
# FASTAPI APP (lifespan starts background tasks)
# FastAPI recommends lifespan over startup/shutdown events. :contentReference[oaicite:3]{index=3}
# -----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_state()
    t1 = asyncio.create_task(candidate_loop())
    t2 = asyncio.create_task(watch_loop())
    await tg_send("✅ Service started (webhook + scanner in one Railway service).", silent=True)

    try:
        yield
    finally:
        t1.cancel()
        t2.cancel()

app = FastAPI(lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True}


def _normalize_auth_header(value: str) -> str:
    v = (value or "").strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    return v


@app.post("/helius")
async def helius_webhook(request: Request):
    # Verify request authenticity using authHeader -> Authorization echo. :contentReference[oaicite:4]{index=4}
    if HELIUS_AUTH_HEADER:
        got = _normalize_auth_header(request.headers.get("Authorization", ""))
        if got != HELIUS_AUTH_HEADER:
            raise HTTPException(status_code=401, detail="Unauthorized")

    payload = await request.json()

    # Helius can send an array of transactions (enhanced)
    txs = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []

    buy_events = 0

    for tx in txs:
        if not isinstance(tx, dict):
            continue
        sig = tx.get("signature")
        ts = tx.get("timestamp") or int(time.time())

        events = tx.get("events") or {}
        swap = (events.get("swap") or {})
        inner_swaps = swap.get("innerSwaps") or []
        if not inner_swaps:
            continue

        for inner in inner_swaps:
            # Find if one of our wallets appears in this innerSwap
            wallet = None
            for ti in inner.get("tokenInputs", []) or []:
                w = ti.get("fromUserAccount")
                if w in WATCH_WALLETS:
                    wallet = w
                    break
            if not wallet:
                for to in inner.get("tokenOutputs", []) or []:
                    w = to.get("toUserAccount")
                    if w in WATCH_WALLETS:
                        wallet = w
                        break
            if not wallet:
                continue

            # Heuristic BUY: spent SOL/USDC/USDT -> received a non-ignored mint
            spent = next((ti for ti in inner.get("tokenInputs", []) or [] if ti.get("fromUserAccount") == wallet), None)
            received = next((to for to in inner.get("tokenOutputs", []) or [] if to.get("toUserAccount") == wallet), None)

            spent_mint = (spent or {}).get("mint")
            recv_mint = (received or {}).get("mint")

            if spent_mint in IGNORE_MINTS and recv_mint and recv_mint not in IGNORE_MINTS:
                buy_events += 1
                ev = {"ts": ts, "signature": sig, "wallet": wallet, "mint": recv_mint}

                # queue for scoring/entry checks (don’t block the webhook response)
                try:
                    candidates_q.put_nowait(ev)
                except asyncio.QueueFull:
                    pass

                # optional immediate wallet signal (silent)
                asyncio.create_task(tg_send(
                    f"👣 Wallet BUY\nWallet: {wallet}\nMint: {recv_mint}\nSig: {sig}",
                    silent=True
                ))

    # Return 200 quickly so Helius doesn’t keep retrying. :contentReference[oaicite:5]{index=5}
    return {"ok": True, "buy_events": buy_events}
