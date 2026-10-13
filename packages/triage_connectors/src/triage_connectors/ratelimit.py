"""Async token bucket.

`rate` tokens are added per second up to `capacity`. acquire() waits until a token is
available, so callers are smoothed to the provider's quota instead of hitting 429s
(VirusTotal's public API, for instance, allows 4 requests/minute).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class TokenBucket:
    def __init__(
        self,
        rate: float,
        capacity: float | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(1.0, rate)
        self._tokens = self.capacity
        self._clock, self._sleep = clock, sleep
        self._updated = clock()
        self._lock = asyncio.Lock()

    @classmethod
    def per_minute(cls, requests: float, burst: float | None = None, **kw) -> TokenBucket:
        return cls(requests / 60.0, burst if burst is not None else 1.0, **kw)

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens

    async def acquire(self, tokens: float = 1.0, *, timeout: float | None = None) -> float:
        """Take `tokens`, waiting if needed. Returns seconds waited. Raises TimeoutError."""
        if tokens > self.capacity:
            raise ValueError("cannot acquire more tokens than the bucket holds")
        waited = 0.0
        async with self._lock:  # FIFO-ish: one waiter refills at a time
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                delay = (tokens - self._tokens) / self.rate
                if timeout is not None and waited + delay > timeout:
                    raise TimeoutError(f"rate limiter would wait {waited + delay:.2f}s > {timeout}s")
                await self._sleep(delay)
                waited += delay
