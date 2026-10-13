import pytest

from triage_connectors import Indicator, IndicatorType, RetryPolicy


class FakeClock:
    """Deterministic monotonic clock whose sleep() advances time instantly."""

    def __init__(self, start: float = 1000.0):
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def fast_retry():
    return RetryPolicy(max_attempts=3, base_delay=0.0, max_delay=0.0, jitter=False)


IP = Indicator(type=IndicatorType.ipv4, value="198.51.100.7")
DOMAIN = Indicator(type=IndicatorType.domain, value="Evil.Example.COM.")
SHA256 = Indicator(type=IndicatorType.sha256, value="A" * 64)
