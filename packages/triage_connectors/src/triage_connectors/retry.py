"""Retry with exponential backoff and full jitter, honouring Retry-After."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

from triage_connectors.errors import ConnectorError, RateLimitedError

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 8.0
    jitter: bool = True

    def backoff(self, attempt: int, rng: random.Random | None = None) -> float:
        """Delay before attempt `attempt + 1` (attempt is 1-based)."""
        ceiling = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        return (rng or random).uniform(0, ceiling) if self.jitter else ceiling


NO_RETRY = RetryPolicy(max_attempts=1)


async def call_with_retry(
    fn: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_retry: Callable[[int, ConnectorError, float], None] | None = None,
) -> T:
    attempt = 1
    while True:
        try:
            return await fn()
        except ConnectorError as exc:
            if not exc.retryable or attempt >= policy.max_attempts:
                raise
            delay = policy.backoff(attempt)
            if isinstance(exc, RateLimitedError) and exc.retry_after is not None:
                if exc.retry_after > policy.max_delay:
                    raise  # quota window is longer than we're willing to block a worker
                delay = max(delay, exc.retry_after)
            if on_retry:
                on_retry(attempt, exc, delay)
            await sleep(delay)
            attempt += 1
