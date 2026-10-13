"""Types, token bucket, retry policy, TTL cache."""

import pytest
from conftest import DOMAIN, IP, FakeClock

from triage_connectors import (
    AuthenticationError,
    EnrichmentResult,
    Indicator,
    IndicatorType,
    RateLimitedError,
    RetryPolicy,
    TokenBucket,
    TTLCache,
    UpstreamError,
    Verdict,
    call_with_retry,
)

# --- types --------------------------------------------------------------------------------


def test_indicators_are_normalised():
    assert DOMAIN.value == "evil.example.com"
    assert Indicator(type=IndicatorType.ipv6, value="2001:DB8::0001").value == "2001:db8::1"
    assert Indicator(type=IndicatorType.md5, value="D41D8CD98F00B204E9800998ECF8427E").value.islower()


@pytest.mark.parametrize(
    "kind, value",
    [("ipv4", "999.1.1.1"), ("ipv4", "2001:db8::1"), ("domain", "localhost"), ("sha256", "abc"), ("md5", "z" * 32)],
)
def test_invalid_indicators_rejected(kind, value):
    with pytest.raises(ValueError):
        Indicator(type=kind, value=value)


def test_result_is_immutable_and_hides_raw():
    r = EnrichmentResult(connector="x", indicator=IP, verdict=Verdict.benign, raw={"secret": 1})
    assert "secret" not in r.model_dump_json()
    with pytest.raises(ValueError):
        r.verdict = Verdict.malicious


# --- token bucket ---------------------------------------------------------------------------


async def test_bucket_allows_burst_then_paces(clock: FakeClock):
    bucket = TokenBucket(rate=2.0, capacity=2, clock=clock, sleep=clock.sleep)
    assert await bucket.acquire() == 0
    assert await bucket.acquire() == 0
    waited = await bucket.acquire()
    assert waited == pytest.approx(0.5)
    waited = await bucket.acquire()
    assert waited == pytest.approx(0.5)


async def test_bucket_refills_over_time(clock: FakeClock):
    bucket = TokenBucket(rate=1.0, capacity=3, clock=clock, sleep=clock.sleep)
    for _ in range(3):
        await bucket.acquire()
    clock.now += 10
    assert bucket.available == pytest.approx(3)  # capped at capacity


async def test_bucket_timeout(clock: FakeClock):
    bucket = TokenBucket.per_minute(4, clock=clock, sleep=clock.sleep)
    await bucket.acquire()
    with pytest.raises(TimeoutError):
        await bucket.acquire(timeout=1.0)  # next token is 15s away


# --- retry ----------------------------------------------------------------------------------


async def test_retries_retryable_errors_then_succeeds(clock: FakeClock):
    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise UpstreamError("x", "HTTP 503", status=503)
        return "ok"

    policy = RetryPolicy(max_attempts=3, base_delay=1, max_delay=10, jitter=False)
    assert await call_with_retry(flaky, policy, sleep=clock.sleep) == "ok"
    assert clock.slept == [1, 2]  # exponential


async def test_non_retryable_raises_immediately(clock: FakeClock):
    async def denied():
        raise AuthenticationError("x", "HTTP 401")

    with pytest.raises(AuthenticationError):
        await call_with_retry(denied, RetryPolicy(max_attempts=5), sleep=clock.sleep)
    assert clock.slept == []


async def test_retry_after_is_honoured_or_gives_up(clock: FakeClock):
    attempts = []

    async def limited():
        attempts.append(1)
        if len(attempts) == 1:
            raise RateLimitedError("x", "429", retry_after=3)
        return "ok"

    policy = RetryPolicy(max_attempts=2, base_delay=0.1, max_delay=5, jitter=False)
    assert await call_with_retry(limited, policy, sleep=clock.sleep) == "ok"
    assert clock.slept == [3]

    async def long_window():
        raise RateLimitedError("x", "429", retry_after=60)

    with pytest.raises(RateLimitedError):
        await call_with_retry(long_window, policy, sleep=clock.sleep)


async def test_retry_exhaustion_raises_last_error(clock: FakeClock):
    async def down():
        raise UpstreamError("x", "HTTP 502", status=502)

    with pytest.raises(UpstreamError):
        await call_with_retry(down, RetryPolicy(max_attempts=3, jitter=False), sleep=clock.sleep)
    assert len(clock.slept) == 2


def test_backoff_is_capped():
    p = RetryPolicy(base_delay=1, max_delay=4, jitter=False)
    assert [p.backoff(n) for n in range(1, 6)] == [1, 2, 4, 4, 4]


# --- cache ----------------------------------------------------------------------------------


async def test_ttl_cache_expiry_and_lru(clock: FakeClock):
    cache = TTLCache(max_entries=2, clock=clock)
    r = EnrichmentResult(connector="x", indicator=IP, verdict=Verdict.benign)
    await cache.set("a", r, ttl=10)
    await cache.set("b", r, ttl=100)
    assert await cache.get("a") is r
    clock.now += 11
    assert await cache.get("a") is None
    await cache.set("c", r, ttl=100)
    await cache.set("d", r, ttl=100)  # evicts the least recently used ("b")
    assert await cache.get("b") is None
    assert len(cache) == 2
    assert (cache.hits, cache.misses) == (1, 2)
