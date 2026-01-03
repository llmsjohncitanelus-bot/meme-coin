from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass(frozen=True)
class Asset:
    """A fungible asset on a chain."""
    address: str                # mint (Solana) or contract (EVM) or "native"
    symbol: str                 # "SOL", "USDC", "WETH", etc.
    amount: float               # UI units (already decimals-adjusted)


@dataclass
class NormalizedEvent:
    chain: str                  # "solana" | "ethereum" | "base" | ...
    network: str                # e.g., "mainnet", "ETH_MAINNET", "BASE_MAINNET"
    tx_hash: str
    timestamp: int              # unix seconds (best effort)
    tracked_wallet: str         # the wallet we care about (must be in watchlist)
    side: str                   # "BUY" | "SELL" | "SWAP" | "TRANSFER"
    spent: Optional[Asset] = None
    received: Optional[Asset] = None
    dex: Optional[str] = None
    meta: Dict = field(default_factory=dict)     # extra provider data
    links: Dict[str, str] = field(default_factory=dict)  # explorer/dex/phantom/etc.
