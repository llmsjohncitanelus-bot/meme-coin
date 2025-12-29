# scoring.py

def clamp(x, lo=0, hi=100):
    return max(lo, min(hi, x))

def safe_get(d, *path, default=0):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur if cur is not None else default

def compute_scores(pair: dict):
    """
    Quick-flip biased scoring:
      - Momentum: mostly 5m txns + 5m volume + buy pressure
      - Safety: mostly liquidity (but not requiring huge liq), plus mild penalties
    Returns: (safety:int, momentum:int, stats:dict)
    """

    liq = float(safe_get(pair, "liquidity", "usd", default=0) or 0)
    vol5m = float(safe_get(pair, "volume", "m5", default=0) or 0)
    vol1h = float(safe_get(pair, "volume", "h1", default=0) or 0)

    chg5m = float(safe_get(pair, "priceChange", "m5", default=0) or 0)

    buys5m = int(safe_get(pair, "txns", "m5", "buys", default=0) or 0)
    sells5m = int(safe_get(pair, "txns", "m5", "sells", default=0) or 0)
    txns5m = buys5m + sells5m
    buy_ratio = (buys5m / txns5m) if txns5m > 0 else 0.0

    fdv = float(pair.get("fdv") or 0)

    # -----------------------------
    # MOMENTUM (0-100)
    # -----------------------------
    momentum = 0

    # Txns burst: 0..60 txns => 0..45 points, 120+ txns => near max
    momentum += clamp((txns5m / 60) * 45)

    # Volume burst: 0..7k => 0..40 points, 15k+ => near max
    momentum += clamp((vol5m / 7000) * 40)

    # 1h volume is just a stabilizer (helps confirm it's not a single blip)
    momentum += clamp((vol1h / 70000) * 10)

    # Buy pressure bonus/penalty
    # Good quick-flip tape is often buy_ratio ~0.55-0.85
    if txns5m >= 20:
        if 0.55 <= buy_ratio <= 0.85:
            momentum += 10
        elif buy_ratio > 0.93 or buy_ratio < 0.45:
            momentum -= 10

    # Anti-chase (but not too harsh)
    if chg5m > 250:
        momentum -= 15
    elif chg5m > 150:
        momentum -= 8

    # If it’s dumping hard already, reduce
    if chg5m < -25:
        momentum -= 10

    momentum = clamp(momentum)

    # -----------------------------
    # SAFETY (0-100)
    # -----------------------------
    safety = 0

    # Liquidity curve that doesn't demand $20k+ to pass:
    # 0..2k => 0..10 points
    # 2k..10k => ramps to ~40
    # 10k..30k => ramps up to ~70+
    if liq <= 0:
        safety += 0
    elif liq < 2000:
        safety += clamp((liq / 2000) * 10)
    else:
        safety += 10
        safety += clamp(((liq - 2000) / 8000) * 30)   # up to +30 by 10k
        safety += clamp(((liq - 10000) / 20000) * 30) # up to +30 by 30k

    # Mild penalties for botty / fragile behavior
    if txns5m >= 40 and (buys5m == 0 or sells5m == 0):
        safety -= 12

    if txns5m >= 40 and (buy_ratio > 0.95 or buy_ratio < 0.40):
        safety -= 10

    # FDV/liquidity sanity (optional)
    if fdv > 0 and liq > 0:
        ratio = fdv / liq
        if ratio > 2500:
            safety -= 15
        elif ratio > 1500:
            safety -= 8

    safety = clamp(safety)

    stats = {
        "liq_usd": liq,
        "txns5m": txns5m,
        "buys5m": buys5m,
        "sells5m": sells5m,
        "buy_ratio": buy_ratio,
        "vol5m": vol5m,
        "vol1h": vol1h,
        "chg5m_pct": chg5m,
        "fdv": fdv,
    }

    return int(safety), int(momentum), stats
