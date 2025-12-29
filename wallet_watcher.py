# wallet_watcher.py
import os
import json
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException
import uvicorn

from telegram_alerts import TelegramAlerter

# -----------------------------
# CONFIG
# -----------------------------
# Your 10 wallets to track
WATCH_WALLETS = {
    "4EtAJ1p8RjqccEVhEhaYnEgQ6kA4JHR8oYqyLFwARUj6",
    "EdCNh8EzETJLFphW8yvdY7rDd8zBiyweiz8DU5gUUUka",
    "8zFZHuSRuDpuAR7J6FzwyF3vKNx4CVW3DFHJerQhc7Zd",
    "8mZYBV8aPvPCo34CyCmt6fWkZRFviAUoBZr1Bn993gro",
    "5CP6zv8a17mz91v6rMruVH6ziC5qAL8GFaJzwrX9Fvup",
    "H2ikJvq8or5MyjvFowD7CDY6fG3Sc2yi4mxTnfovXy3K",
    "2h7s3FpSvc6v2oHke6Uqg191B5fPCeFTmMGnh5oPWhX7",
    "HWdeCUjBvPP1HJ5oCJt7aNsvMWpWoDgiejUWvfFX6T7R",
    "4DPxYoJ5DgjvXPUtZdT3CYUZ3EEbSPj4zMNEVFJTd1Ts",
    "Hwz4BDgtDRDBTScpEKDawshdKatZJh6z1SJYmRUxTxKE",
}

# Mint addresses to treat as "not the memecoin target"
# (wSOL + common stables)
IGNORE_MINTS = {
    "So11111111111111111111111111111111111111112",  # wSOL
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",  # USDT
}

FEED_FILE = os.environ.get("WALLET_FEED_FILE", "wallet_candidates.jsonl")

# Helius auth header you set when creating the webhook (recommended)
# If set, we will require Authorization header == this value
HELIUS_AUTH_HEADER = os.environ.get("HELIUS_AUTH_HEADER", "").strip()

# Telegram
BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"].strip()
CHAT_ID = int(os.environ["TELEGRAM_CHAT_ID"].strip())
alerter = TelegramAlerter(bot_token=BOT_TOKEN, chat_id=CHAT_ID)

app = FastAPI()


def _as_list(payload: Any) -> List[Dict[str, Any]]:
    """Helius can POST an array of txs; be permissive."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        # sometimes wrapped like {"transactions":[...]} depending on tooling
        txs = payload.get("transactions")
        if isinstance(txs, list):
            return [x for x in txs if isinstance(x, dict)]
        # or a single tx dict
        return [payload]
    return []


def _pick_wallet_for_swap(inner: Dict[str, Any]) -> Optional[str]:
    # Try to locate the wallet in tokenInputs/fromUserAccount or tokenOutputs/toUserAccount
    for ti in inner.get("tokenInputs", []) or []:
        w = ti.get("fromUserAccount")
        if w in WATCH_WALLETS:
            return w
    for to in inner.get("tokenOutputs", []) or []:
        w = to.get("toUserAccount")
        if w in WATCH_WALLETS:
            return w
    return None


def _summarize_swap(inner: Dict[str, Any], wallet: str) -> Dict[str, Any]:
    """Return a compact summary and a candidate 'mint' if it's a buy-like event."""
    spent = None
    received = None

    for ti in inner.get("tokenInputs", []) or []:
        if ti.get("fromUserAccount") == wallet:
            spent = ti
            break

    for to in inner.get("tokenOutputs", []) or []:
        if to.get("toUserAccount") == wallet:
            received = to
            break

    spent_mint = (spent or {}).get("mint")
    recv_mint = (received or {}).get("mint")

    spent_amt = (spent or {}).get("tokenAmount")
    recv_amt = (received or {}).get("tokenAmount")

    action = "SWAP"
    candidate_mint = None

    # Heuristic: "BUY" if wallet spent ignored mint and received a non-ignored mint
    if spent_mint in IGNORE_MINTS and recv_mint and recv_mint not in IGNORE_MINTS:
        action = "BUY"
        candidate_mint = recv_mint
    # "SELL" if wallet spent non-ignored mint and received ignored mint
    elif spent_mint and spent_mint not in IGNORE_MINTS and recv_mint in IGNORE_MINTS:
        action = "SELL"
        candidate_mint = spent_mint  # token being sold

    return {
        "action": action,
        "candidate_mint": candidate_mint,
        "spent_mint": spent_mint,
        "spent_amt": spent_amt,
        "recv_mint": recv_mint,
        "recv_amt": recv_amt,
    }


def _append_feed(event: Dict[str, Any]) -> None:
    # Append JSONL line (coin_finder will tail this file)
    with open(FEED_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/helius")
async def helius_webhook(request: Request):
    # Verify request authenticity via Authorization header (recommended by Helius)
    # You set this value when creating the webhook ("authHeader"). :contentReference[oaicite:4]{index=4}
    if HELIUS_AUTH_HEADER:
        got = request.headers.get("Authorization", "")
        if got != HELIUS_AUTH_HEADER:
            raise HTTPException(status_code=401, detail="Unauthorized")

    payload = await request.json()
    txs = _as_list(payload)

    buy_events = 0

    for tx in txs:
        sig = tx.get("signature")
        ts = tx.get("timestamp") or int(time.time())
        events = tx.get("events") or {}
        swap = events.get("swap") or {}

        inner_swaps = swap.get("innerSwaps") or []
        if not inner_swaps:
            continue

        for inner in inner_swaps:
            wallet = _pick_wallet_for_swap(inner)
            if not wallet:
                continue

            s = _summarize_swap(inner, wallet)

            # Only write & alert on BUY events (you can change this)
            if s["action"] != "BUY" or not s["candidate_mint"]:
                continue

            event = {
                "ts": ts,
                "signature": sig,
                "wallet": wallet,
                "action": s["action"],
                "mint": s["candidate_mint"],
                "spent_mint": s["spent_mint"],
                "spent_amt": s["spent_amt"],
                "recv_mint": s["recv_mint"],
                "recv_amt": s["recv_amt"],
            }

            _append_feed(event)
            buy_events += 1

            # Telegram alert (wallet buy signal)
            msg = (
                "👣 Wallet BUY signal\n"
                f"Wallet: {wallet}\n"
                f"Mint: {event['mint']}\n"
                f"Spent: {event['spent_amt']} ({event['spent_mint']})\n"
                f"Received: {event['recv_amt']} ({event['recv_mint']})\n"
                f"Sig: {sig}"
            )
            try:
                alerter.send(msg, silent=False)
            except Exception:
                pass

    # Return 200 quickly so Helius doesn't retry. :contentReference[oaicite:5]{index=5}
    return {"ok": True, "buy_events": buy_events}


if __name__ == "__main__":
    # For local test only. Helius requires a public HTTPS URL, not localhost. :contentReference[oaicite:6]{index=6}
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
