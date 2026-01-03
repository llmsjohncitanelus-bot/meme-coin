from __future__ import annotations

import urllib.parse


def explorer_tx_link(chain: str, tx_hash: str) -> str:
    if chain == "solana":
        return f"https://solscan.io/tx/{tx_hash}"
    if chain == "ethereum":
        return f"https://etherscan.io/tx/{tx_hash}"
    if chain == "base":
        return f"https://basescan.org/tx/{tx_hash}"
    return ""


def phantom_caip19_solana(mint: str) -> str:
    # CAIP-19 format used by Phantom deeplinks
    # Example shown in Phantom docs uses solana:101/address:<mint>
    return f"solana:101/address:{mint}"


def phantom_fungible_link_solana(mint: str) -> str:
    token = urllib.parse.quote(phantom_caip19_solana(mint), safe="")
    return f"https://phantom.app/ul/v1/fungible?token={token}"


def phantom_swap_link_solana(buy_mint: str, sell_mint: str = "") -> str:
    buy = urllib.parse.quote(phantom_caip19_solana(buy_mint), safe="")
    sell = urllib.parse.quote(phantom_caip19_solana(sell_mint), safe="") if sell_mint else ""
    return f"https://phantom.app/ul/v1/swap?buy={buy}&sell={sell}"
