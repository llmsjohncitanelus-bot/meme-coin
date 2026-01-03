from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from core.models import Asset, NormalizedEvent


SOL_SYMBOL = "SOL"
NATIVE_ADDR = "native"  # internal marker


def parse_helius_webhook(payload: Any, watched_wallets: set[str]) -> List[NormalizedEvent]:
    """
    Helius webhooks typically POST a JSON array of transaction objects (enhanced or raw).
    We'll treat it as a list and attempt to infer net SOL/token flows for a watched wallet.
    """
    out: List[NormalizedEvent] = []
    if not isinstance(payload, list):
        return out

    watched = {w.strip() for w in watched_wallets if w}

    for tx in payload:
        if not isinstance(tx, dict):
            continue

        sig = tx.get("signature") or tx.get("transactionSignature") or ""
        if not sig:
            continue

        # Find which tracked wallet is involved
        tracked_wallet = _find_tracked_wallet(tx, watched)
        if not tracked_wallet:
            continue

        net = _compute_net_flows(tx, tracked_wallet)
        spent, received = _pick_spent_received(net)

        side = "TRANSFER"
        if spent and received:
            side = _classify_side_solana(spent, received)

        ts = int(tx.get("timestamp") or 0)

        out.append(
            NormalizedEvent(
                chain="solana",
                network="mainnet",
                tx_hash=sig,
                timestamp=ts,
                tracked_wallet=tracked_wallet,
                side=side,
                spent=spent,
                received=received,
                dex=(tx.get("type") or None),
                meta={"helius_type": tx.get("type"), "raw": tx},
            )
        )

    return out


def _find_tracked_wallet(tx: Dict[str, Any], watched: set[str]) -> Optional[str]:
    # feePayer is common in enhanced payloads
    fee_payer = tx.get("feePayer")
    if fee_payer in watched:
        return fee_payer

    # tokenTransfers sometimes contain fromUserAccount/toUserAccount
    for t in (tx.get("tokenTransfers") or []):
        f = t.get("fromUserAccount")
        to = t.get("toUserAccount")
        if f in watched:
            return f
        if to in watched:
            return to

    # nativeTransfers sometimes contain fromUserAccount/toUserAccount
    for n in (tx.get("nativeTransfers") or []):
        f = n.get("fromUserAccount")
        to = n.get("toUserAccount")
        if f in watched:
            return f
        if to in watched:
            return to

    return None


def _compute_net_flows(tx: Dict[str, Any], wallet: str) -> Dict[Tuple[str, str], float]:
    """
    Net flows for wallet: incoming positive, outgoing negative.
    Keyed by (address, symbol). For SPL tokens: address=mint, symbol=symbol if present.
    """
    net: Dict[Tuple[str, str], float] = {}

    def add(k: Tuple[str, str], amt: float):
        net[k] = net.get(k, 0.0) + amt

    # SOL transfers (lamports)
    for n in (tx.get("nativeTransfers") or []):
        lamports = float(n.get("amount") or 0.0)
        sol = lamports / 1_000_000_000.0

        frm = n.get("fromUserAccount")
        to = n.get("toUserAccount")

        if to == wallet:
            add((NATIVE_ADDR, SOL_SYMBOL), sol)
        if frm == wallet:
            add((NATIVE_ADDR, SOL_SYMBOL), -sol)

    # Token transfers
    for t in (tx.get("tokenTransfers") or []):
        mint = (t.get("mint") or "").strip()
        sym = (t.get("tokenSymbol") or "TOKEN").upper()
        amt = float(t.get("tokenAmount") or 0.0)

        frm = t.get("fromUserAccount")
        to = t.get("toUserAccount")

        if to == wallet:
            add((mint or "unknown", sym), amt)
        if frm == wallet:
            add((mint or "unknown", sym), -amt)

    return net


def _pick_spent_received(net: Dict[Tuple[str, str], float]) -> Tuple[Optional[Asset], Optional[Asset]]:
    spent = None
    received = None

    neg = [(k, v) for k, v in net.items() if v < 0]
    pos = [(k, v) for k, v in net.items() if v > 0]

    if neg:
        (addr, sym), v = min(neg, key=lambda kv: kv[1])
        spent = Asset(address=addr, symbol=sym, amount=abs(v))

    if pos:
        (addr, sym), v = max(pos, key=lambda kv: kv[1])
        received = Asset(address=addr, symbol=sym, amount=v)

    return spent, received


def _classify_side_solana(spent: Asset, received: Asset) -> str:
    quote_syms = {"SOL", "USDC", "USDT"}
    s_spent = spent.symbol.upper()
    s_recv = received.symbol.upper()

    if s_spent in quote_syms and s_recv not in quote_syms:
        return "BUY"
    if s_recv in quote_syms and s_spent not in quote_syms:
        return "SELL"
    return "SWAP"
