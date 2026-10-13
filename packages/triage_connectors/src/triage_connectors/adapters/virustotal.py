"""VirusTotal API v3 (https://docs.virustotal.com/reference/overview)."""

from __future__ import annotations

import base64
from typing import Any

import httpx

from triage_connectors.base import HttpConnector
from triage_connectors.errors import ConfigurationError
from triage_connectors.ratelimit import TokenBucket
from triage_connectors.types import EnrichmentResult, Indicator, IndicatorType, Verdict

_COLLECTION = {
    IndicatorType.ipv4: "ip_addresses",
    IndicatorType.ipv6: "ip_addresses",
    IndicatorType.domain: "domains",
    IndicatorType.url: "urls",
    IndicatorType.md5: "files",
    IndicatorType.sha1: "files",
    IndicatorType.sha256: "files",
}


def url_id(url: str) -> str:
    """VT identifies URLs by unpadded urlsafe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalConnector(HttpConnector):
    name = "virustotal"
    supported_types = frozenset(_COLLECTION)
    default_base_url = "https://www.virustotal.com/api/v3"

    #: engines flagging "malicious" at or above which the verdict is malicious
    malicious_threshold = 3

    def __init__(self, api_key: str | None, **kw: Any):
        if not api_key:
            raise ConfigurationError(self.name, "api_key is required")
        kw.setdefault("rate_limiter", TokenBucket.per_minute(4))  # public API quota
        kw.setdefault("ttl", 24 * 3600.0)
        super().__init__(**kw)
        self._api_key = api_key

    def build_request(self, indicator: Indicator) -> httpx.Request:
        ident = url_id(indicator.value) if indicator.type is IndicatorType.url else indicator.value
        return self.client.build_request(
            "GET",
            f"{self.base_url}/{_COLLECTION[indicator.type]}/{ident}",
            headers={"x-apikey": self._api_key, "accept": "application/json"},
        )

    def parse(self, indicator: Indicator, payload: dict[str, Any]) -> EnrichmentResult:
        attrs = payload["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        if malicious >= self.malicious_threshold:
            verdict = Verdict.malicious
        elif malicious or suspicious >= 2:
            verdict = Verdict.suspicious
        elif harmless:
            verdict = Verdict.benign
        else:
            verdict = Verdict.unknown
        tags = list(attrs.get("tags", []))
        if label := attrs.get("popular_threat_classification", {}).get("suggested_threat_label"):
            tags.append(label)
        return EnrichmentResult(
            connector=self.name,
            indicator=indicator,
            verdict=verdict,
            score=round(100 * malicious / total, 1) if total else None,
            summary=f"{malicious}/{total} engines malicious, reputation {attrs.get('reputation', 0)}",
            tags=tuple(tags[:10]),
            raw=payload,
        )
