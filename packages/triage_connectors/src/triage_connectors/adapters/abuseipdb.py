"""AbuseIPDB API v2 /check (https://docs.abuseipdb.com/#check-endpoint)."""

from __future__ import annotations

from typing import Any

import httpx

from triage_connectors.base import HttpConnector
from triage_connectors.errors import ConfigurationError
from triage_connectors.ratelimit import TokenBucket
from triage_connectors.types import EnrichmentResult, Indicator, IndicatorType, Verdict


class AbuseIPDBConnector(HttpConnector):
    name = "abuseipdb"
    supported_types = frozenset({IndicatorType.ipv4, IndicatorType.ipv6})
    default_base_url = "https://api.abuseipdb.com/api/v2"

    malicious_score = 75
    suspicious_score = 25

    def __init__(self, api_key: str | None, *, max_age_days: int = 90, **kw: Any):
        if not api_key:
            raise ConfigurationError(self.name, "api_key is required")
        kw.setdefault("rate_limiter", TokenBucket.per_minute(60, burst=5))
        kw.setdefault("ttl", 6 * 3600.0)
        super().__init__(**kw)
        self._api_key = api_key
        self.max_age_days = max_age_days

    def build_request(self, indicator: Indicator) -> httpx.Request:
        return self.client.build_request(
            "GET",
            f"{self.base_url}/check",
            params={"ipAddress": indicator.value, "maxAgeInDays": self.max_age_days},
            headers={"Key": self._api_key, "Accept": "application/json"},
        )

    def parse(self, indicator: Indicator, payload: dict[str, Any]) -> EnrichmentResult:
        data = payload["data"]
        score = int(data["abuseConfidenceScore"])
        reports = int(data.get("totalReports", 0))
        if data.get("isWhitelisted"):
            verdict = Verdict.benign
        elif score >= self.malicious_score:
            verdict = Verdict.malicious
        elif score >= self.suspicious_score:
            verdict = Verdict.suspicious
        elif reports == 0:
            verdict = Verdict.unknown
        else:
            verdict = Verdict.benign
        tags = tuple(t for t in (data.get("usageType"), data.get("countryCode"), data.get("isp")) if t)
        return EnrichmentResult(
            connector=self.name,
            indicator=indicator,
            verdict=verdict,
            score=float(score),
            summary=f"abuse confidence {score}%, {reports} reports",
            tags=tags,
            raw=payload,
        )
