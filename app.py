# app.py
# Multi-chain webhook + Telegram alerts + Tap-to-execute trading (Option 1)
#
# Endpoints:
#   POST /helius        (Solana Helius webhook receiver)
#   POST /webhook/evm   (Alchemy Address Activity receiver)
#   POST /telegram      (Telegram callback receiver for Approve/Ignore buttons)
#
# Trading:
#   Solana swaps via Jupiter (quote -> swap tx -> sign -> send)
#   Coinbase orders via Advanced Trade API (JWT Bearer -> create order)
#
# Notes:
# - This is designed for "approve-to-trade" safety.
# - Set EXECUTION_ENABLED=0 to test safely (default).
# - Jupiter endpoints have evolved; this uses swap/v1 style endpoints.  (See docs)
# - Coinbase Advanced Trade uses Bearer JWT auth and order_configuration blocks.

import os
import json
import time
import hmac
import uuid
import base64
import hashlib
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict, deque

import requests
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse

# --- optional deps for Solana signing (required if you enable Jupiter execution) ---
# pip install solders base58
try:
    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction
    import base58
except Exception:
    Keypair = None
    VersionedTransaction = None
    base58 = None

# --- optional deps for Coinbase JWT ---
# pip install pyjwt cryptography
try:
    import jwt  # PyJWT
except Exception:
    jwt = None

# -----------------------------
# Logging
# -----------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL)
log = logging.getLogger("wallet-webhook")

# -----------------------------
# Helpers
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

def now_ts() -> int:
    return int(time.time())

# -----------------------------
# Telegram
# -----------------------------
TELEGRAM_BOT_TOKEN = getenv_required("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = int(getenv_required("TELEGRAM_CHAT_ID"))
TG_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

TG_MIN_INTERVAL = float(os.getenv("TG_MIN_INTERVAL", "0.8"))
TG_DISABLE_PREVIEW = os.getenv("TG_DISABLE_PREVIEW", "0").strip() not in ("0", "false", "False")  # default allow previews

_last_tg_ts = 0.0
tg_session = requests.Session()

def tg_send(text: str, reply_markup: Optional[Dict[str, Any]] = None, silent: bool = False) -> Dict[str, Any]:
    global _last_tg_ts
    wait = TG_MIN_INTERVAL - (time.time() - _last_tg_ts)
    if wait > 0:
        time.sleep(wait)

    payload: Dict[str, Any] = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": clamp_str(text),
        "disable_notification": bool(silent),
        "disable_web_page_preview": bool(TG_DISABLE_PREVIEW),
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup

    r = tg_session.post(f"{TG_BASE}/sendMessage", json=payload, timeout=20)
    r.raise_for_status()
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data)
    _last_tg_ts = time.time()
    return data

def tg_answer_callback(callback_query_id: str, text: str = "", show_alert: bool = False) -> None:
    r = tg_session.post(
        f"{TG_BASE}/answerCallbackQuery",
        json={"callback_query_id": callback_query_id, "text": text, "show_alert": show_alert},
        timeout=20,
    )
    r.raise_for_status()

# -----------------------------
# Security: optional shared secrets
# -----------------------------
HELIUS_AUTH_HEADER = os.getenv("HELIUS_AUTH_HEADER", "").strip()
EVM_WEBHOOK_SECRET = os.getenv("EVM_WEBHOOK_SECRET", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

def check_secret(actual: Optional[str], expected: str, label: str) -> None:
    if not expected:
        return
    if not actual or actual.strip() != expected:
        raise HTTPException(status_code=401, detail=f"Unauthorized ({label})")

# -----------------------------
# Watchlists
# -----------------------------
WATCH_WALLETS_SOL = parse_csv_set("WATCH_WALLETS_SOL")       # Solana base58 addresses
WATCH_WALLETS_EVM = {w.lower() for w in parse_csv_set("WATCH_WALLETS_EVM")}  # EVM 0x lower

def is_tracked_sol(addr: str) -> bool:
    if not WATCH_WALLETS_SOL:
        return True
    return addr in WATCH_WALLETS_SOL

def is_tracked_evm(addr: str) -> bool:
    if not WATCH_WALLETS_EVM:
        return True
    return (addr or "").lower() in WATCH_WALLETS_EVM

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
# Dexscreener enrichment (optional)
# -----------------------------
DEXSCREENER_ENABLED = os.getenv("DEXSCREENER_ENABLED", "1").strip() not in ("0", "false", "False")
DEX_TIMEOUT = float(os.getenv("DEX_TIMEOUT", "10"))
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
    if not token_addr:
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
WSOL_MINT = "So11111111111111111111111111111111111111112"

def solscan_tx(sig: str) -> str:
    return f"https://solscan.io/tx/{sig}"

def phantom_token_sol(mint: str) -> str:
    return f"https://phantom.com/tokens/solana/{mint}"

def phantom_ul_token(chain_id: str, mint_or_contract: str) -> str:
    # best-effort universal link token id format
    # Solana mainnet: solana:101/address:<mint>
    # Ethereum: eip155:1/erc20:<contract>
    # Base: eip155:8453/erc20:<contract>
    if chain_id == "solana":
        token_id = f"solana:101/address:{mint_or_contract}"
    elif chain_id == "ethereum":
        token_id = f"eip155:1/erc20:{mint_or_contract}"
    elif chain_id == "base":
        token_id = f"eip155:8453/erc20:{mint_or_contract}"
    else:
        token_id = mint_or_contract

    return "https://phantom.app/ul/v1/fungible?token=" + urllib.parse.quote(token_id, safe="")

def phantom_ul_swap(chain_id: str, buy_token: str, sell_token: str) -> str:
    def tid(chain: str, tok: str) -> str:
        if chain == "solana":
            return f"solana:101/address:{tok}"
        if chain == "ethereum":
            return f"eip155:1/erc20:{tok}"
        if chain == "base":
            return f"eip155:8453/erc20:{tok}"
        return tok

    buy_id = tid(chain_id, buy_token)
    sell_id = tid(chain_id, sell_token)
    return (
        "https://phantom.app/ul/v1/swap?"
        + "buy=" + urllib.parse.quote(buy_id, safe="")
        + "&sell=" + urllib.parse.quote(sell_id, safe="")
    )

def jupiter_swap_link(symbol: str) -> str:
    # This is just a human-friendly link (not API)
    return f"https://jup.ag/swap/{urllib.parse.quote(symbol)}-SOL"

# -----------------------------
# Trading controls
# -----------------------------
EXECUTION_ENABLED = os.getenv("EXECUTION_ENABLED", "0").strip() in ("1", "true", "True")

# Solana/Jupiter trade sizing
SOL_TRADE_AMOUNT_SOL = float(os.getenv("SOL_TRADE_AMOUNT_SOL", "0.25"))
JUP_SLIPPAGE_BPS = int(os.getenv("JUP_SLIPPAGE_BPS", "100"))  # 1%
SOLANA_RPC_URL = os.getenv("SOLANA_RPC_URL", "").strip()
SOLANA_PRIVATE_KEY = os.getenv("SOLANA_PRIVATE_KEY", "").strip()
JUP_API_KEY = os.getenv("JUP_API_KEY", "").strip()
JUP_BASE_URL = os.getenv("JUP_BASE_URL", "https://api.jup.ag").strip().rstrip("/")

# Coinbase trade sizing
COINBASE_BASE_URL = os.getenv("COINBASE_BASE_URL", "https://api.coinbase.com").strip().rstrip("/")
COINBASE_KEY_NAME = os.getenv("COINBASE_KEY_NAME", "").strip()
COINBASE_PRIVATE_KEY = os.getenv("COINBASE_PRIVATE_KEY", "").strip()
COINBASE_DEFAULT_QUOTE = os.getenv("COINBASE_DEFAULT_QUOTE", "USD").strip().upper()
COINBASE_DEFAULT_USD = float(os.getenv("COINBASE_DEFAULT_USD", "25"))

# Optional mapping like: "SOL:SOL-USD,ETH:ETH-USD,BTC:BTC-USD"
def parse_symbol_map(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    raw = (raw or "").strip()
    if not raw:
        return out
    for part in raw.split(","):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().upper()] = v.strip()
    return out

COINBASE_SYMBOL_MAP = parse_symbol_map(os.getenv("COINBASE_SYMBOL_MAP", ""))

# -----------------------------
# Pending trades (Approve/Ignore)
# -----------------------------
PENDING_TTL_SEC = int(os.getenv("PENDING_TTL_SEC", "1800"))  # 30 minutes default
PENDING: Dict[str, Dict[str, Any]] = {}

def pending_put(trade: Dict[str, Any]) -> str:
    trade_id = trade["id"]
    PENDING[trade_id] = trade
    return trade_id

def pending_get(trade_id: str) -> Optional[Dict[str, Any]]:
    t = PENDING.get(trade_id)
    if not t:
        return None
    if now_ts() - int(t.get("created_ts", 0)) > PENDING_TTL_SEC:
        PENDING.pop(trade_id, None)
        return None
    return t

def pending_delete(trade_id: str) -> None:
    PENDING.pop(trade_id, None)

# -----------------------------
# Solana: Helius parsing (simple net-flow for SWAP)
# -----------------------------
def helius_iter_txs(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        # sometimes it's {"transactions":[...]}
        txs = payload.get("transactions")
        if isinstance(txs, list):
            return [x for x in txs if isinstance(x, dict)]
        return [payload]
    return []

def sol_net_flows(tx: Dict[str, Any], wallet: str) -> Dict[str, float]:
    """Net token flow by mint for wallet (positive=in, negative=out)."""
    net: Dict[str, float] = defaultdict(float)

    for t in (tx.get("tokenTransfers") or []):
        if not isinstance(t, dict):
            continue
        frm = t.get("fromUserAccount") or ""
        to = t.get("toUserAccount") or ""
        mint = t.get("mint") or ""
        amt = t.get("tokenAmount")
        try:
            amt = float(amt)
        except Exception:
            amt = 0.0

        if to == wallet:
            net[mint] += amt
        if frm == wallet:
            net[mint] -= amt

    # sometimes SOL is only in nativeTransfers
    for nt in (tx.get("nativeTransfers") or []):
        if not isinstance(nt, dict):
            continue
        frm = nt.get("fromUserAccount") or ""
        to = nt.get("toUserAccount") or ""
        lamports_or_sol = nt.get("amount", 0)

        try:
            val = float(lamports_or_sol)
        except Exception:
            val = 0.0

        # Heuristic: if huge, assume lamports
        sol = val / 1e9 if val > 1e7 else val
        if to == wallet:
            net[WSOL_MINT] += sol
        if frm == wallet:
            net[WSOL_MINT] -= sol

    return net

def pick_spent_received(net: Dict[str, float]) -> Tuple[Optional[Tuple[str, float]], Optional[Tuple[str, float]]]:
    neg = [(m, v) for m, v in net.items() if v < 0]
    pos = [(m, v) for m, v in net.items() if v > 0]
    spent = min(neg, key=lambda x: x[1]) if neg else None
    recv = max(pos, key=lambda x: x[1]) if pos else None
    if spent:
        spent = (spent[0], abs(spent[1]))
    return spent, recv

def sol_side(spent: Optional[Tuple[str, float]], recv: Optional[Tuple[str, float]]) -> str:
    if spent and recv:
        if spent[0] == WSOL_MINT and recv[0] != WSOL_MINT:
            return "BUY"
        if recv[0] == WSOL_MINT and spent[0] != WSOL_MINT:
            return "SELL"
        return "SWAP"
    return "TRANSFER"

# -----------------------------
# Jupiter execution (Solana)
# -----------------------------
def load_solana_keypair() -> Keypair:
    if Keypair is None or base58 is None:
        raise RuntimeError("Missing Solana deps. Install: pip install solders base58")
    if not SOLANA_PRIVATE_KEY:
        raise RuntimeError("SOLANA_PRIVATE_KEY not set")

    raw = SOLANA_PRIVATE_KEY.strip()
    if raw.startswith("["):
        arr = json.loads(raw)
        secret = bytes(arr)
    else:
        secret = base58.b58decode(raw)

    # secret should be 64 bytes (secret+pub)
    return Keypair.from_bytes(secret)

def solana_rpc(method: str, params: list) -> Any:
    if not SOLANA_RPC_URL:
        raise RuntimeError("SOLANA_RPC_URL not set")
    r = requests.post(
        SOLANA_RPC_URL,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=25,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data.get("result")

def jup_headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if JUP_API_KEY:
        h["x-api-key"] = JUP_API_KEY
    return h

def jup_quote(input_mint: str, output_mint: str, amount_int: int, slippage_bps: int) -> Dict[str, Any]:
    url = f"{JUP_BASE_URL}/swap/v1/quote"
    params = {
        "inputMint": input_mint,
        "outputMint": output_mint,
        "amount": str(amount_int),
        "slippageBps": str(slippage_bps),
    }
    r = requests.get(url, params=params, headers=jup_headers(), timeout=20)
    r.raise_for_status()
    return r.json()

def jup_swap(quote_resp: Dict[str, Any], user_pubkey: str) -> Dict[str, Any]:
    url = f"{JUP_BASE_URL}/swap/v1/swap"
    body = {
        "quoteResponse": quote_resp,
        "userPublicKey": user_pubkey,
        "wrapAndUnwrapSol": True,
        "dynamicComputeUnitLimit": True,
    }
    r = requests.post(url, json=body, headers=jup_headers(), timeout=25)
    r.raise_for_status()
    return r.json()

def execute_jupiter_buy(output_mint: str) -> str:
    kp = load_solana_keypair()
    user_pubkey = str(kp.pubkey())

    # Spend SOL_TRADE_AMOUNT_SOL worth of SOL (via WSOL mint) in lamports
    lamports = int(SOL_TRADE_AMOUNT_SOL * 1e9)

    quote = jup_quote(WSOL_MINT, output_mint, lamports, JUP_SLIPPAGE_BPS)
    swap_resp = jup_swap(quote, user_pubkey)

    swap_tx_b64 = swap_resp.get("swapTransaction")
    if not swap_tx_b64:
        raise RuntimeError(f"Jupiter swap response missing swapTransaction: {swap_resp}")

    raw_tx = base64.b64decode(swap_tx_b64)
    tx = VersionedTransaction.from_bytes(raw_tx)
    signed = VersionedTransaction(tx.message, [kp])
    signed_b64 = base64.b64encode(bytes(signed)).decode()

    sig = solana_rpc("sendTransaction", [signed_b64, {"encoding": "base64", "maxRetries": 2}])
    return sig

# -----------------------------
# Coinbase JWT + order execution
# -----------------------------
def coinbase_jwt(request_method: str, request_host: str, request_path: str) -> str:
    if jwt is None:
        raise RuntimeError("Missing PyJWT. Install: pip install pyjwt cryptography")
    if not COINBASE_KEY_NAME or not COINBASE_PRIVATE_KEY:
        raise RuntimeError("COINBASE_KEY_NAME / COINBASE_PRIVATE_KEY not set")

    uri = f"{request_method} {request_host}{request_path}"
    now = int(time.time())
    nonce = uuid.uuid4().hex

    payload = {
        "sub": COINBASE_KEY_NAME,
        "iss": "cdp",
        "nbf": now,
        "exp": now + 120,   # 2 minutes
        "uri": uri,
    }
    headers = {
        "kid": COINBASE_KEY_NAME,
        "nonce": nonce,
    }

    token = jwt.encode(
        payload,
        COINBASE_PRIVATE_KEY,
        algorithm="ES256",
        headers=headers,
    )
    return token

def coinbase_request(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
    # Advanced Trade API base is api.coinbase.com with /api/v3/brokerage/*
    host = "api.coinbase.com"
    token = coinbase_jwt(method.upper(), host, path)
    url = f"{COINBASE_BASE_URL}{path}"
    r = requests.request(
        method.upper(),
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body,
        timeout=25,
    )
    r.raise_for_status()
    return r.json()

def coinbase_product_for_symbol(symbol: str) -> Optional[str]:
    sym = (symbol or "").upper()
    if not sym:
        return None
    if sym in COINBASE_SYMBOL_MAP:
        return COINBASE_SYMBOL_MAP[sym]
    # fallback guess:
    return f"{sym}-{COINBASE_DEFAULT_QUOTE}"

def execute_coinbase_market_buy(symbol: str, usd: float) -> str:
    product_id = coinbase_product_for_symbol(symbol)
    if not product_id:
        raise RuntimeError("No product id for symbol")

    body = {
        "client_order_id": uuid.uuid4().hex,
        "product_id": product_id,
        "side": "BUY",
        "order_configuration": {
            "market_market_ioc": {
                "quote_size": f"{usd:.2f}"
            }
        }
    }
    resp = coinbase_request("POST", "/api/v3/brokerage/orders", body=body)
    # response formats can vary; return something useful
    return json.dumps(resp, separators=(",", ":"))[:800]

# -----------------------------
# EVM: (keep your existing Alchemy handler, but minimal here)
# -----------------------------
ALCHEMY_SIGNING_KEY = os.getenv("ALCHEMY_SIGNING_KEY", "").encode()

def verify_alchemy_signature(raw_body: bytes, sig_header: Optional[str]) -> None:
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
# App + summaries
# -----------------------------
app = FastAPI()

helius_summary = defaultdict(int)
alchemy_summary = defaultdict(int)

def log_summary(tag: str, s: Dict[str, Any]) -> None:
    log.info("%s_summary=%s", tag, json.dumps(s, separators=(",", ":")))

@app.get("/")
def root():
    return {
        "ok": True,
        "execution_enabled": EXECUTION_ENABLED,
        "watch_sol": len(WATCH_WALLETS_SOL),
        "watch_evm": len(WATCH_WALLETS_EVM),
        "dexscreener": DEXSCREENER_ENABLED,
    }

@app.get("/debug/summary")
def debug_summary():
    return {"ok": True, "helius_summary": dict(helius_summary), "alchemy_summary": dict(alchemy_summary)}

# -----------------------------
# Telegram callback receiver (Approve/Ignore)
# -----------------------------
@app.post("/telegram")
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: Optional[str] = Header(default=None, alias="X-Telegram-Bot-Api-Secret-Token"),
):
    check_secret(x_telegram_bot_api_secret_token, TELEGRAM_WEBHOOK_SECRET, "telegram_secret")
    update = await request.json()

    cb = update.get("callback_query")
    if not cb:
        return {"ok": True}

    cb_id = cb.get("id", "")
    data = (cb.get("data") or "").strip()
    if not data:
        tg_answer_callback(cb_id, "No action", show_alert=False)
        return {"ok": True}

    # callback format: approve:jupiter:<trade_id> | approve:coinbase:<trade_id> | ignore:<trade_id>
    try:
        parts = data.split(":")
        if parts[0] == "ignore":
            trade_id = parts[1]
            pending_delete(trade_id)
            tg_answer_callback(cb_id, "Ignored ✅")
            tg_send(f"❌ Ignored trade {trade_id}")
            return {"ok": True}

        if parts[0] == "approve":
            route = parts[1]
            trade_id = parts[2]
            trade = pending_get(trade_id)
            if not trade:
                tg_answer_callback(cb_id, "Expired / missing trade", show_alert=True)
                return {"ok": True}

            tg_answer_callback(cb_id, f"Approved ({route})…", show_alert=False)

            if not EXECUTION_ENABLED:
                tg_send(f"🧪 DRY RUN: would execute {route} for trade {trade_id}\n{json.dumps(trade, indent=2)[:1200]}")
                pending_delete(trade_id)
                return {"ok": True}

            # Execute
            if route == "jupiter":
                if trade.get("chain") != "solana":
                    tg_send("⚠️ This trade is not Solana/Jupiter compatible.")
                else:
                    mint = trade.get("mint")
                    sig = execute_jupiter_buy(mint)
                    tg_send(f"✅ Jupiter swap sent!\nSig: {sig}\n{solscan_tx(sig)}")

            elif route == "coinbase":
                symbol = trade.get("symbol")
                usd = float(trade.get("usd", COINBASE_DEFAULT_USD))
                resp = execute_coinbase_market_buy(symbol, usd)
                tg_send(f"✅ Coinbase order placed!\n{resp}")

            else:
                tg_send(f"⚠️ Unknown route: {route}")

            pending_delete(trade_id)
            return {"ok": True}

        tg_answer_callback(cb_id, "Unknown action", show_alert=False)
        return {"ok": True}

    except Exception as e:
        log.exception("telegram handler error: %s", e)
        try:
            tg_answer_callback(cb_id, f"Error: {e}", show_alert=True)
        except Exception:
            pass
        return {"ok": True}

# -----------------------------
# Solana webhook (Helius)  ✅ fixes your 404 problem
# -----------------------------
@app.post("/helius")
async def webhook_helius(request: Request, authorization: Optional[str] = Header(default=None)):
    check_secret(authorization, HELIUS_AUTH_HEADER, "helius_auth")
    raw = await request.body()
    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    helius_summary["received"] += 1

    txs = helius_iter_txs(payload)
    sent = 0

    for tx in txs:
        try:
            sig = tx.get("signature") or tx.get("transactionSignature") or ""
            tx_type = (tx.get("type") or "").upper()
            source = tx.get("source") or ""

            if not sig:
                continue

            # Find a tracked wallet involved (simple: scan token transfers)
            wallets = set()
            for t in (tx.get("tokenTransfers") or []):
                if isinstance(t, dict):
                    wallets.add(t.get("fromUserAccount") or "")
                    wallets.add(t.get("toUserAccount") or "")
            for nt in (tx.get("nativeTransfers") or []):
                if isinstance(nt, dict):
                    wallets.add(nt.get("fromUserAccount") or "")
                    wallets.add(nt.get("toUserAccount") or "")

            wallet = next((w for w in wallets if w and is_tracked_sol(w)), None)
            if not wallet:
                helius_summary["untracked"] += 1
                continue

            net = sol_net_flows(tx, wallet)
            spent, recv = pick_spent_received(net)
            side = sol_side(spent, recv)

            # ignore spam transfers unless explicitly needed
            if side == "TRANSFER":
                helius_summary["transfer_ignored"] += 1
                continue

            dedupe_key = f"sol:{wallet}:{sig}:{side}"
            if not remember_once(dedupe_key):
                helius_summary["dedupe"] += 1
                continue

            # Identify "token mint" we care about (non-WSOL leg when possible)
            mint = None
            if side == "BUY" and recv and recv[0] != WSOL_MINT:
                mint = recv[0]
            elif side == "SELL" and spent and spent[0] != WSOL_MINT:
                mint = spent[0]
            elif side == "SWAP":
                # prefer non-WSOL receive, else non-WSOL spent
                if recv and recv[0] != WSOL_MINT:
                    mint = recv[0]
                elif spent and spent[0] != WSOL_MINT:
                    mint = spent[0]

            # Dexscreener enrichment (Solana)
            dex = dex_enrich("solana", mint) if mint else None

            emoji = "🟢" if side == "BUY" else "🔴" if side == "SELL" else "🟡"
            lines = [
                f"{emoji} {side} (solana)",
                f"Wallet: {wallet}",
            ]
            if spent:
                lines.append(f"Spent: {spent[1]:.6g} {spent[0][:6]}…")
            if recv:
                lines.append(f"Received: {recv[1]:.6g} {recv[0][:6]}…")
            if source:
                lines.append(f"Source: {source}")
            if tx_type:
                lines.append(f"Type: {tx_type}")

            if mint:
                # Phantom links (this is what disappeared for you)
                lines.append(f"Phantom token: {phantom_token_sol(mint)}")
                lines.append(f"Phantom (in-app): {phantom_ul_token('solana', mint)}")
                # Swap deep link: buy=mint sell=WSOL by default
                lines.append(f"Phantom swap: {phantom_ul_swap('solana', mint, WSOL_MINT)}")
                # Jupiter human link
                lines.append(f"Jupiter: {jupiter_swap_link('TOKEN')}".replace("TOKEN", "SOL"))  # simple generic

                if dex:
                    lines.append(f"Dexscreener: {dex.get('url')}")
                    price = dex.get("priceUsd")
                    liq = dex.get("liqUsd", 0.0)
                    v5 = dex.get("vol5m", 0.0)
                    v1 = dex.get("vol1h", 0.0)
                    if price is not None:
                        try:
                            lines.append(f"Price: ${float(price):.8f} | Liquidity: ${liq:,.0f}")
                        except Exception:
                            lines.append(f"Price: {price} | Liquidity: ${liq:,.0f}")
                    else:
                        lines.append(f"Liquidity: ${liq:,.0f}")
                    lines.append(f"Vol(5m): ${v5:,.0f} | Vol(1h): ${v1:,.0f}")

            lines.append(f"Sig: {sig}")
            lines.append(solscan_tx(sig))
            msg = "\n".join(lines)

            # Create pending trade intent (tap-to-execute)
            # We'll offer Jupiter execution when we have a mint and it's a BUY signal.
            trade_id = uuid.uuid4().hex[:12]
            trade = {
                "id": trade_id,
                "created_ts": now_ts(),
                "chain": "solana",
                "side": side,
                "mint": mint,
                "symbol": "SOL",   # also allow Coinbase SOL buy as a fallback
                "usd": COINBASE_DEFAULT_USD,
                "sig": sig,
                "wallet": wallet,
            }
            pending_put(trade)

            keyboard = {"inline_keyboard": []}
            row = []
            if mint and side == "BUY":
                row.append({"text": "✅ Approve (Jupiter)", "callback_data": f"approve:jupiter:{trade_id}"})
            row.append({"text": "✅ Buy SOL (Coinbase)", "callback_data": f"approve:coinbase:{trade_id}"})
            row.append({"text": "❌ Ignore", "callback_data": f"ignore:{trade_id}"})
            keyboard["inline_keyboard"].append(row)

            tg_send(msg, reply_markup=keyboard)
            sent += 1
            helius_summary["sent"] += 1

        except Exception as e:
            helius_summary["exceptions"] += 1
            log.exception("helius processing error: %s", e)

    helius_summary["ignored"] += max(0, len(txs) - sent)
    log_summary("helius", dict(helius_summary))
    return {"ok": True, "received": len(txs), "sent": sent}

# -----------------------------
# EVM webhook (Alchemy) - minimal keep-alive
# -----------------------------
@app.post("/webhook/evm")
async def webhook_evm(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_alchemy_signature: Optional[str] = Header(default=None, alias="X-Alchemy-Signature"),
):
    check_secret(authorization, EVM_WEBHOOK_SECRET, "evm_secret")
    raw = await request.body()
    verify_alchemy_signature(raw, x_alchemy_signature)

    try:
        payload = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    alchemy_summary["received"] += 1

    # If you want: reuse your existing detailed Address Activity parsing here.
    # For now, we just ack to prove the endpoint exists and stops 404.
    log_summary("alchemy", dict(alchemy_summary))
    return {"ok": True}

# -----------------------------
# Error handler
# -----------------------------
@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})
