import os
import time
import json
import random
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import defaultdict, deque

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from telegram_alerts import TelegramAlerter
from scoring import compute_scores

# -----------------------------
# CONFIG (Preset A: 30–90 min holds)
# -----------------------------
CHAIN = "solana"
POLL_SECONDS = 15

# Entry thresholds (wallet-driven signals can be a bit lower)
MIN_SAFETY = 15
MIN_MOMENTUM = 48

# Floors (confirm it's real before alert)
MIN_LIQ_USD = 1500
MIN_TXNS_5M = 18
MIN_VOL5_USD = 650

MIN_BUY_RATIO = 0.45
MAX_BUY_RATIO = 0.95
MAX_CHG5M_FOR_ENTRY = 300

# Exit rules (Preset A)
TRAIL_STOP_PCT = 0.35
TIME_STOP_SECONDS = 60 * 60
LIQ_DROP_PCT = 0.20
MIN_HOLD_SECONDS = 20 * 60

COOLDOWN_SECONDS = 120

STATE_FILE = "coin_finder_state.json"
WALLET_FEED_FILE = os.environ.get("WALLET_FEED_FILE", "wallet_candidates.jsonl")

# Dexscreener
TOKEN_PAIRS_URL = "https://api.dexscreener.com/token-pairs/v1/{chain}/{token}"

REQUEST_TIMEOUT = 45
ERROR_ALERT_COOLDOWN = 300

DEBUG_REJECTIONS = True
DEBUG_SAMPLE_RATE = 0.01

# -----------------------------
# TELEGRAM
# -----------------------------
BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"].strip()
CHAT_ID = int(os.environ["TELEGRAM_CHAT_ID"].strip())
alerter = TelegramAlerter(bot_token=BOT_TOKEN, chat_id=CHAT_ID)

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
# HELPERS
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

    return {
        "ts": ts,
        "price": price,
        "liq": liq,
        "vol5": vol5,
        "buys": buys,
        "sells": sells,
        "txns": txns,
        "chg5": chg5,
        "buy_ratio": buy_ratio,
    }

def liquidity_drop(hist: deque, drop_pct: float) -> bool:
    if len(hist) < 2:
        return False
    a, b = list(hist)[-2], list(hist)[-1]
    if a["liq"] <= 0:
        return False
    return (b["liq"] / a["liq"]) < (1 - drop_pct)

def trailing_stop_trigger(peak: float, current: float, stop_pct: float) -> bool:
    if peak <= 0:
        return False
    return current <= peak * (1 - stop_pct)

def maybe_debug(msg: str):
    if not DEBUG_REJECTIONS:
        return
    if random.random() >= DEBUG_SAMPLE_RATE:
        return
    try:
        alerter.send(f"🔎 reject: {msg}", silent=True)
    except Exception:
        pass

def get_token_pairs(chain: str, token: str) -> List[Dict[str, Any]]:
    url = TOKEN_PAIRS_URL.format(chain=chain, token=token)
    r = session.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def pick_best_pair(pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    def liq_usd(p: Dict[str, Any]) -> float:
        return float((p.get("liquidity") or {}).get("usd") or 0)
    return max(pairs, key=liq_usd)

def fmt_entry_watch(mint: str, pair: Dict[str, Any], safety: int, momentum: int, s: Dict[str, Any], source: str) -> str:
    base = pair.get("baseToken") or {}
    name = base.get("name") or "Unknown"
    symbol = base.get("symbol") or ""
    pair_url = pair.get("url") or ""
    return (
        f"🟢 ENTRY WATCH (Preset A: 30–90m)\n"
        f"{name} ({symbol})\n"
        f"Source: {source}\n"
        f"Safety: {safety}/100 | Momentum: {momentum}/100\n"
        f"Price: {s['price']:.8f}\n"
        f"Liq: ${s['liq']:,.0f} | Txns(5m): {s['txns']} (B{s['buys']}/S{s['sells']})\n"
        f"Vol(5m): ${s['vol5']:,.0f} | BuyRatio: {s['buy_ratio']:.2f} | Δ5m: {s['chg5']}%\n"
        f"Mint: {mint}\n"
        f"Pair: {pair_url}"
    )

def fmt_exit_alert(reason: str, mint: str, pair: Dict[str, Any], s: Dict[str, Any], extra: str = "") -> str:
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
    if extra:
        msg += "\n" + extra
    return msg

# -----------------------------
# STATE (alerted + cooldown + feed offset)
# -----------------------------
def load_state() -> Tuple[Set[str], Dict[str, float], int]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        alerted = set(data.get("alerted", []))
        cooldown_until = {k: float(v) for k, v in (data.get("cooldown_until", {}) or {}).items()}
        feed_pos = int(data.get("feed_pos", 0) or 0)
        return alerted, cooldown_until, feed_pos
    except FileNotFoundError:
        return set(), {}, 0
    except Exception:
        return set(), {}, 0

def save_state(alerted: Set[str], cooldown_until: Dict[str, float], feed_pos: int) -> None:
    data = {
        "alerted": list(alerted)[-50000:],
        "cooldown_until": cooldown_until,
        "feed_pos": feed_pos,
        "updated_at": time.time(),
    }
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

def read_wallet_feed(feed_pos: int) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    if not os.path.exists(WALLET_FEED_FILE):
        return events, feed_pos

    with open(WALLET_FEED_FILE, "rb") as f:
        f.seek(feed_pos)
        chunk = f.read()
        new_pos = f.tell()

    if not chunk:
        return events, feed_pos

    for line in chunk.splitlines():
        try:
            ev = json.loads(line.decode("utf-8"))
            if isinstance(ev, dict):
                events.append(ev)
        except Exception:
            continue

    return events, new_pos

# -----------------------------
# MAIN
# -----------------------------
def main():
    alerted, cooldown_until, feed_pos = load_state()
    alerter.send("✅ coin_finder started (wallet-webhook feed + Preset A holds).")

    history = defaultdict(lambda: deque(maxlen=10))
    watch: Dict[str, Dict[str, Any]] = {}  # mint -> peak,last_high_ts,started_ts

    last_error_alert = 0.0

    while True:
        now = time.time()

        try:
            # 1) Manage exits for active watches
            for mint in list(watch.keys()):
                w = watch[mint]
                try:
                    pairs = get_token_pairs(CHAIN, mint)
                    if not pairs:
                        continue
                    best = pick_best_pair(pairs)
                    s = snapshot_from_pair(best, time.time())
                    history[mint].append(s)

                    if s["price"] > w["peak"]:
                        w["peak"] = s["price"]
                        w["last_high_ts"] = s["ts"]

                    # Liquidity drop is immediate
                    if liquidity_drop(history[mint], LIQ_DROP_PCT):
                        alerter.send(fmt_exit_alert("LIQUIDITY DROP", mint, best, s))
                        watch.pop(mint, None)
                        continue

                    held_for = s["ts"] - w["started_ts"]
                    if held_for < MIN_HOLD_SECONDS:
                        continue

                    if trailing_stop_trigger(w["peak"], s["price"], TRAIL_STOP_PCT):
                        extra = f"Peak: {w['peak']:.8f} | Trail: {int(TRAIL_STOP_PCT*100)}% | Held: {int(held_for/60)}m"
                        alerter.send(fmt_exit_alert("TRAIL STOP", mint, best, s, extra=extra))
                        watch.pop(mint, None)
                        continue

                    if (s["ts"] - w["last_high_ts"]) >= TIME_STOP_SECONDS:
                        extra = f"No new highs for {int(TIME_STOP_SECONDS/60)}m | Held: {int(held_for/60)}m"
                        alerter.send(fmt_exit_alert("TIME STOP", mint, best, s, extra=extra))
                        watch.pop(mint, None)
                        continue

                except Exception:
                    continue

            # 2) Process NEW wallet feed events
            feed_events, feed_pos = read_wallet_feed(feed_pos)

            for ev in feed_events:
                if ev.get("action") != "BUY":
                    continue
                mint = ev.get("mint")
                wallet = ev.get("wallet", "")
                sig = ev.get("signature", "")

                if not mint:
                    continue

                # skip already alerted or watching
                if mint in alerted or mint in watch:
                    continue

                # cooldown skip
                until = float(cooldown_until.get(mint, 0))
                if now < until:
                    continue

                try:
                    pairs = get_token_pairs(CHAIN, mint)
                    if not pairs:
                        maybe_debug(f"{mint} no pairs yet (from wallet {wallet})")
                        cooldown_until[mint] = now + COOLDOWN_SECONDS
                        continue

                    best = pick_best_pair(pairs)
                    s = snapshot_from_pair(best, time.time())
                    history[mint].append(s)

                    # floors first
                    if s["liq"] < MIN_LIQ_USD or s["txns"] < MIN_TXNS_5M or s["vol5"] < MIN_VOL5_USD:
                        maybe_debug(f"{mint} floors liq={s['liq']:.0f} txns={s['txns']} vol5={s['vol5']:.0f}")
                        cooldown_until[mint] = now + COOLDOWN_SECONDS
                        continue

                    if not (MIN_BUY_RATIO <= s["buy_ratio"] <= MAX_BUY_RATIO):
                        maybe_debug(f"{mint} buy_ratio {s['buy_ratio']:.2f} out of range")
                        cooldown_until[mint] = now + COOLDOWN_SECONDS
                        continue

                    if s["chg5"] > MAX_CHG5M_FOR_ENTRY:
                        maybe_debug(f"{mint} chg5 {s['chg5']:.1f}% too hot")
                        cooldown_until[mint] = now + COOLDOWN_SECONDS
                        continue

                    safety, momentum, _stats = compute_scores(best)
                    if safety < MIN_SAFETY or momentum < MIN_MOMENTUM:
                        maybe_debug(f"{mint} score S{safety}/{MIN_SAFETY} M{momentum}/{MIN_MOMENTUM}")
                        cooldown_until[mint] = now + COOLDOWN_SECONDS
                        continue

                    source = f"wallet {wallet} (sig {sig[:8]}…)"
                    alerter.send(fmt_entry_watch(mint, best, safety, momentum, s, source=source))

                    watch[mint] = {
                        "peak": s["price"],
                        "last_high_ts": s["ts"],
                        "started_ts": s["ts"],
                    }
                    alerted.add(mint)
                    cooldown_until.pop(mint, None)

                except Exception as e:
                    maybe_debug(f"{mint} processing error: {e}")
                    cooldown_until[mint] = now + COOLDOWN_SECONDS

            save_state(alerted, cooldown_until, feed_pos)

        except Exception as e:
            now2 = time.time()
            if now2 - last_error_alert > ERROR_ALERT_COOLDOWN:
                try:
                    alerter.send(f"⚠️ coin_finder error: {e}", silent=True)
                except Exception:
                    pass
                last_error_alert = now2

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
