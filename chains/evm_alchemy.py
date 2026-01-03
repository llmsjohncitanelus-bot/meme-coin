from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from core.models import Asset, NormalizedEvent


def _lower(s: str) -> str:
    return (s or "").lower()


def parse_alchemy_address_activity(payload: Dict[str, Any], watched_wallets: set[str]) -> List[NormalizedEvent]:
    """
    Expects payload like:
      { "type":"ADDRESS_ACTIVITY", "event": { "network": "...", "activity":[ ... ] } }
    """
    out: List[NormalizedEvent] = []
    if not isinstance(payload, dict):
        return out

    typ = payload.get("type")
    event = payload.get("event") or {}
    network = event.get("network") or "unknown"
    activity = event.get("activity") or []

    if typ != "ADDRESS_ACTIVITY" or not isinstance(activity, list):
        return out

    watched = {_lower(w) for w in watched_wallets if w}

    # Group by tx hash, and track which watched wallet was involved
    by_hash: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in activity:
        h = a.get("hash")
        if not h:
            continue
        by_hash[h].append(a)

    for tx_hash, items in by_hash.items():
        # Identify the watched wallet involved
        tracked_wallet = _find_tracked_wallet(items, watched)
        if not tracked_wallet:
            continue

        net = _compute_net_flows(items, tracked_wallet)
        spent, received = _pick_spent_received(net)

        if spent and received:
            side = _classify_side(spent, received)
        else:
            side = "TRANSFER"

        # timestamp not always included; use 0 if missing
        # blockNum is hex; we won't convert to time here in skeleton
        ts = 0

        out.append(
            NormalizedEvent(
                chain=_chain_from_network(network),
                network=network,
                tx_hash=tx_hash,
                timestamp=ts,
                tracked_wallet=tracked_wallet,
                side=side,
                spent=spent,
                received=received,
                dex=None,
                meta={"alchemy_items": items},
            )
        )

    return out


def _chain_from_network(network: str) -> str:
    n = (network or "").upper()
    if "BASE" in n:
        return "base"
    return "ethereum"


def _find_tracked_wallet(items: List[Dict[str, Any]], watched: set[str]) -> Optional[str]:
    for a in items:
        f = _lower(a.get("fromAddress", ""))
        t = _lower(a.get("toAddress", ""))
        if f in watched:
            return f
        if t in watched:
            return t
    return None


def _asset_id(a: Dict[str, Any]) -> Tuple[str, str]:
    """
    Returns (address, symbol).
    For tokens: rawContract.address
    For native ETH transfers: address="native", symbol="ETH"
    """
    sym = (a.get("asset") or "").upper() or "UNKNOWN"
    raw = a.get("rawContract") or {}
    addr = (raw.get("address") or "").lower()
    if not addr and sym == "ETH":
        addr = "native"
    if not addr:
        addr = "unknown"
    return addr, sym


def _compute_net_flows(items: List[Dict[str, Any]], wallet: str) -> Dict[Tuple[str, str], float]:
    """
    Net flow for tracked wallet: incoming positive, outgoing negative.
    Keyed by (asset_address, symbol).
    """
    w = _lower(wallet)
    net: Dict[Tuple[str, str], float] = defaultdict(float)

    for a in items:
        addr, sym = _asset_id(a)
        val = a.get("value")
        try:
            amt = float(val or 0.0)
        except Exception:
            amt = 0.0

        f = _lower(a.get("fromAddress", ""))
        t = _lower(a.get("toAddress", ""))

        if t == w:
            net[(addr, sym)] += amt
        if f == w:
            net[(addr, sym)] -= amt

    return dict(net)


def _pick_spent_received(net: Dict[Tuple[str, str], float]) -> Tuple[Optional[Asset], Optional[Asset]]:
    spent = None
    received = None

    # spent: most negative
    neg = [(k, v) for k, v in net.items() if v < 0]
    pos = [(k, v) for k, v in net.items() if v > 0]

    if neg:
        (addr, sym), v = min(neg, key=lambda kv: kv[1])  # most negative
        spent = Asset(address=addr, symbol=sym, amount=abs(v))

    if pos:
        (addr, sym), v = max(pos, key=lambda kv: kv[1])  # biggest incoming
        received = Asset(address=addr, symbol=sym, amount=v)

    return spent, received


def _classify_side(spent: Asset, received: Asset) -> str:
    quote_syms = {"ETH", "WETH", "USDC", "USDT", "DAI"}
    s_spent = spent.symbol.upper()
    s_recv = received.symbol.upper()

    if s_spent in quote_syms and s_recv not in quote_syms:
        return "BUY"
    if s_recv in quote_syms and s_spent not in quote_syms:
        return "SELL"
    return "SWAP"
