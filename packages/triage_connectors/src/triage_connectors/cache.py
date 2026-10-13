"""Result caches. Any object with async get/set satisfies `CacheBackend`."""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from triage_connectors.types import EnrichmentResult


class CacheBackend(Protocol):
    async def get(self, key: str) -> EnrichmentResult | None: ...
    async def set(self, key: str, value: EnrichmentResult, ttl: float) -> None: ...


class TTLCache:
    """In-process LRU cache with per-entry TTL."""

    def __init__(self, max_entries: int = 10_000, *, clock: Callable[[], float] = time.monotonic):
        self.max_entries = max_entries
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, EnrichmentResult]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    async def get(self, key: str) -> EnrichmentResult | None:
        item = self._data.get(key)
        if item is None:
            self.misses += 1
            return None
        expires, value = item
        if expires <= self._clock():
            del self._data[key]
            self.misses += 1
            return None
        self._data.move_to_end(key)
        self.hits += 1
        return value

    async def set(self, key: str, value: EnrichmentResult, ttl: float) -> None:
        if ttl <= 0:
            return
        self._data[key] = (self._clock() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class NullCache:
    async def get(self, key: str) -> EnrichmentResult | None:
        return None

    async def set(self, key: str, value: EnrichmentResult, ttl: float) -> None:
        return None
