from __future__ import annotations

import time
from typing import Any, Dict, Optional

import requests


class DexscreenerClient:
    """
    Official endpoints (docs):
      - GET https://api.dexscreener.com/token-pairs/v1/{chainId}/{tokenAddress}
      - Rate limit for pairs endpoints: 300 req/min
    """
    BASE = "https://api.dexscreener.com"

    def __init__(self, ttl_seconds: int = 45):
        self.ttl = ttl_seconds
        self.cache: Dict[str, tuple[float, Any]] = {}
        self.session = requests.Session()

    def _cache_get(self, key: str) -> Optional[Any]:
        item = self.cache.get(key)
        if not item:
            return None
        ts, val = item
        if (time.time() - ts) > self.ttl:
            self.cache.pop(key, None)
            return None
        return val

    def _cache_set(self, key: str, val: Any) -> None:
        self.cache[key] = (time.time(), val)

    def get_best_pair(self, chain_id: str, token_address: str) -> Optional[Dict[str, Any]]:
        """
        Returns the pool/pair with highest liquidity.usd for this token.
        """
        token_address = token_address.strip()
        if not token_address:
            return None

        key = f"pairs:{chain_id}:{token_address}"
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        url = f"{self.BASE}/token-pairs/v1/{chain_id}/{token_address}"
        r = self.session.get(url, timeout=20)
        if r.status_code == 429:
            # Rate limited: fail soft
            return None
        r.raise_for_status()
        pairs = r.json() or []
        if not pairs:
            self._cache_set(key, None)
            return None

        def liq_usd(p: Dict[str, Any]) -> float:
            liq = (p.get("liquidity") or {})
            return float(liq.get("usd") or 0.0)

        best = max(pairs, key=liq_usd)
        self._cache_set(key, best)
        return best
