from __future__ import annotations

import time
from collections import deque
from typing import Dict, Optional

from core.models import NormalizedEvent
from core.telegram_client import TelegramClient
from enrich.dexscreener import DexscreenerClient
from links import explorer_tx_link, phantom_fungible_link_solana, phantom_swap_link_solana


class AlertEngine:
    def __init__(
        self,
        telegram: TelegramClient,
        dexscreener: DexscreenerClient,
        chain_for_dexscreener: Dict[str, str],
        quote_symbols_by_chain: Dict[str, set[str]],
        min_liq_usd: float = 0.0,
    ):
        self.telegram = telegram
        self.dex = dexscreener
        self.chain_map = chain_for_dexscreener
        self.quote_symbols_by_chain = quote_symbols_by_chain
        self.min_liq_usd = float(min_liq_usd)

        # Simple in-memory dedupe (works fine on 1 instance; for multi-instance use Redis)
        self._dedupe = set()
        self._dedupe_q = deque(maxlen=50000)

        # Summary counters
        self.summary = {
            "received": 0,
            "sent": 0,
            "ignored": 0,
            "dedupe": 0,
            "exceptions": 0,
        }

    def _dedupe_key(self, ev: NormalizedEvent) -> str:
        return f"{ev.chain}:{ev.tracked_wallet}:{ev.tx_hash}:{ev.side}"

    def _remember(self, key: str) -> bool:
        if key in self._dedupe:
            return False
        self._dedupe.add(key)
        self._dedupe_q.append(key)
        # prune
        while len(self._dedupe) > self._dedupe_q.maxlen:
            old = self._dedupe_q.popleft()
            self._dedupe.discard(old)
        return True

    def process(self, ev: NormalizedEvent, silent: bool = False) -> None:
        self.summary["received"] += 1
        try:
            key = self._dedupe_key(ev)
            if not self._remember(key):
                self.summary["dedupe"] += 1
                return

            # Build base links
            ev.links["explorer_tx"] = explorer_tx_link(ev.chain, ev.tx_hash)

            # Enrich with Dexscreener if we can identify a "main token"
            main_token_addr = self._pick_main_token(ev)
            ds_info = None
            if main_token_addr:
                ds_chain = self.chain_map.get(ev.chain)
                if ds_chain:
                    ds_info = self.dex.get_best_pair(ds_chain, main_token_addr)

            # Optional liquidity gate (keeps spam down)
            if ds_info and self.min_liq_usd > 0:
                liq_usd = float(((ds_info.get("liquidity") or {}).get("usd")) or 0.0)
                if liq_usd < self.min_liq_usd:
                    self.summary["ignored"] += 1
                    return

            msg = self._format_message(ev, ds_info)
            if not msg.strip():
                self.summary["ignored"] += 1
                return

            self.telegram.send(msg, silent=silent)
            self.summary["sent"] += 1

        except Exception:
            self.summary["exceptions"] += 1
            raise

    def _pick_main_token(self, ev: NormalizedEvent) -> Optional[str]:
        """
        Pick the 'non-quote' side as the token to enrich.
        """
        quotes = self.quote_symbols_by_chain.get(ev.chain, set())
        candidates = []
        if ev.spent:
            candidates.append(ev.spent)
        if ev.received:
            candidates.append(ev.received)

        # prefer a token that is not in quotes
        for a in candidates:
            if a and a.symbol and a.symbol.upper() not in quotes and a.address:
                return a.address

        # fallback: received token
        if ev.received and ev.received.address:
            return ev.received.address

        return None

    def _format_message(self, ev: NormalizedEvent, ds_pair: Optional[Dict]) -> str:
        lines = []
        lines.append(f"{'🟢' if ev.side == 'BUY' else '🔴' if ev.side == 'SELL' else '🟡'} {ev.side} ({ev.chain})")
        lines.append(f"Wallet: {ev.tracked_wallet}")
        lines.append(f"Tx: {ev.tx_hash}")

        if ev.spent:
            lines.append(f"Spent: {ev.spent.amount:.6g} {ev.spent.symbol} ({ev.spent.address})")
        if ev.received:
            lines.append(f"Received: {ev.received.amount:.6g} {ev.received.symbol} ({ev.received.address})")

        # Dexscreener enrich
        if ds_pair:
            price = ds_pair.get("priceUsd")
            liq = (ds_pair.get("liquidity") or {}).get("usd")
            vol5 = (ds_pair.get("volume") or {}).get("m5")
            vol1h = (ds_pair.get("volume") or {}).get("h1")
            pair_url = ds_pair.get("url") or ""

            lines.append("—")
            if price is not None:
                lines.append(f"PriceUSD: {price}")
            if liq is not None:
                try:
                    lines.append(f"LiqUSD: ${float(liq):,.0f}")
                except Exception:
                    lines.append(f"LiqUSD: {liq}")
            if vol5 is not None or vol1h is not None:
                try:
                    lines.append(f"Vol(5m/1h): ${float(vol5 or 0):,.0f} / ${float(vol1h or 0):,.0f}")
                except Exception:
                    pass
            if pair_url:
                lines.append(f"Dexscreener: {pair_url}")

        # Chain-specific convenience links
        if ev.chain == "solana":
            # Add Phantom links when we can identify a mint
            mint = None
            if ev.received and ev.received.address and ev.received.address != "native":
                mint = ev.received.address
            elif ev.spent and ev.spent.address and ev.spent.address != "native":
                mint = ev.spent.address

            if mint:
                lines.append("—")
                lines.append(f"Phantom Token: {phantom_fungible_link_solana(mint)}")
                # Prefill buy=<mint>, sell left blank (defaults SOL in Phantom)
                lines.append(f"Phantom Swap: {phantom_swap_link_solana(mint)}")

        if ev.links.get("explorer_tx"):
            lines.append(f"Explorer: {ev.links['explorer_tx']}")

        return "\n".join(lines)
