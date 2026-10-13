"""HttpConnector: the shared machinery every HTTP adapter inherits.

    enrich(indicator)
      -> type check -> cache lookup
      -> retry( rate-limit -> request -> map status to typed error -> parse )
      -> cache store (shorter TTL for "unknown")

Subclasses implement `build_request` and `parse` only.
"""

from __future__ import annotations

import abc
import email.utils
import time
from typing import Any, ClassVar

import httpx

from triage_connectors.cache import CacheBackend, NullCache
from triage_connectors.errors import (
    AuthenticationError,
    ConnectorTimeoutError,
    InvalidResponseError,
    RateLimitedError,
    UnsupportedIndicatorError,
    UpstreamError,
)
from triage_connectors.ratelimit import TokenBucket
from triage_connectors.retry import RetryPolicy, call_with_retry
from triage_connectors.types import EnrichmentResult, Indicator, IndicatorType, Verdict


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        parsed = email.utils.parsedate_to_datetime(value)
        return max(0.0, parsed.timestamp() - time.time()) if parsed else None


class HttpConnector(abc.ABC):
    name: ClassVar[str]
    supported_types: ClassVar[frozenset[IndicatorType]]
    default_base_url: ClassVar[str]

    def __init__(
        self,
        *,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
        rate_limiter: TokenBucket | None = None,
        retry_policy: RetryPolicy | None = None,
        cache: CacheBackend | None = None,
        ttl: float = 3600.0,
        unknown_ttl: float = 600.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.base_url = (base_url or self.default_base_url).rstrip("/")
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(timeout=timeout, transport=transport)
        self.rate_limiter = rate_limiter
        self.retry_policy = retry_policy or RetryPolicy()
        self.cache = cache if cache is not None else NullCache()  # an empty TTLCache is falsy
        self.ttl, self.unknown_ttl = ttl, unknown_ttl
        self.stats = {"requests": 0, "cache_hits": 0, "retries": 0, "errors": 0}

    # --- subclass hooks -----------------------------------------------------------------

    @abc.abstractmethod
    def build_request(self, indicator: Indicator) -> httpx.Request: ...

    @abc.abstractmethod
    def parse(self, indicator: Indicator, payload: dict[str, Any]) -> EnrichmentResult: ...

    def on_not_found(self, indicator: Indicator) -> EnrichmentResult:
        return self.unknown(indicator, "not found")

    # --- helpers --------------------------------------------------------------------------

    def unknown(self, indicator: Indicator, summary: str = "no data") -> EnrichmentResult:
        return EnrichmentResult(connector=self.name, indicator=indicator, verdict=Verdict.unknown, summary=summary)

    def cache_key(self, indicator: Indicator) -> str:
        return f"{self.name}:{indicator.type}:{indicator.value}"

    # --- public API -----------------------------------------------------------------------

    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        if indicator.type not in self.supported_types:
            raise UnsupportedIndicatorError(self.name, f"{indicator.type} not supported")
        key = self.cache_key(indicator)
        hit = await self.cache.get(key)
        if hit is not None:
            self.stats["cache_hits"] += 1
            return hit.model_copy(update={"cached": True})

        def _count_retry(*_: object) -> None:
            self.stats["retries"] += 1

        try:
            result = await call_with_retry(lambda: self._fetch(indicator), self.retry_policy, on_retry=_count_retry)
        except Exception:
            self.stats["errors"] += 1
            raise
        ttl = self.unknown_ttl if result.verdict is Verdict.unknown else self.ttl
        await self.cache.set(key, result, ttl)
        return result

    async def _fetch(self, indicator: Indicator) -> EnrichmentResult:
        if self.rate_limiter is not None:
            await self.rate_limiter.acquire()
        request = self.build_request(indicator)
        self.stats["requests"] += 1
        try:
            response = await self.client.send(request)
        except httpx.TimeoutException as exc:
            raise ConnectorTimeoutError(self.name, f"timeout: {exc}") from exc
        except httpx.TransportError as exc:
            raise UpstreamError(self.name, f"transport error: {exc}") from exc

        status = response.status_code
        if status == 404:
            return self.on_not_found(indicator)
        if status in (401, 403):
            raise AuthenticationError(self.name, f"HTTP {status}")
        if status == 429:
            raise RateLimitedError(self.name, "HTTP 429", parse_retry_after(response.headers.get("retry-after")))
        if status >= 500:
            raise UpstreamError(self.name, f"HTTP {status}", status=status, retryable=True)
        if status >= 400:
            raise UpstreamError(self.name, f"HTTP {status}: {response.text[:200]}", status=status, retryable=False)

        try:
            payload = response.json()
            return self.parse(indicator, payload)
        except (ValueError, KeyError, TypeError) as exc:
            raise InvalidResponseError(self.name, f"unexpected response: {exc}") from exc

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
