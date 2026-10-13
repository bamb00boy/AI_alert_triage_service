"""Enrichment connector SDK.

    from triage_connectors import Indicator, IndicatorType, EnrichmentRunner
    from triage_connectors.adapters import VirusTotalConnector

    async with VirusTotalConnector(api_key="...") as vt:
        result = await vt.enrich(Indicator(type=IndicatorType.ipv4, value="198.51.100.7"))
"""

from triage_connectors.base import HttpConnector
from triage_connectors.cache import CacheBackend, NullCache, TTLCache
from triage_connectors.errors import (
    AuthenticationError,
    ConfigurationError,
    ConnectorError,
    ConnectorTimeoutError,
    InvalidResponseError,
    RateLimitedError,
    UnsupportedIndicatorError,
    UpstreamError,
)
from triage_connectors.fixtures import FixtureTransport
from triage_connectors.protocol import Connector
from triage_connectors.ratelimit import TokenBucket
from triage_connectors.retry import NO_RETRY, RetryPolicy, call_with_retry
from triage_connectors.runner import EnrichmentRunner, RunReport, aggregate
from triage_connectors.types import EnrichmentResult, Indicator, IndicatorType, Verdict

__version__ = "0.1.0"

__all__ = [
    "NO_RETRY",
    "AuthenticationError",
    "CacheBackend",
    "ConfigurationError",
    "Connector",
    "ConnectorError",
    "ConnectorTimeoutError",
    "EnrichmentResult",
    "EnrichmentRunner",
    "FixtureTransport",
    "HttpConnector",
    "Indicator",
    "IndicatorType",
    "InvalidResponseError",
    "NullCache",
    "RateLimitedError",
    "RetryPolicy",
    "RunReport",
    "TTLCache",
    "TokenBucket",
    "UnsupportedIndicatorError",
    "UpstreamError",
    "Verdict",
    "aggregate",
    "call_with_retry",
]
