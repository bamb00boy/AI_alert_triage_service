"""Adapter for the project's own ti-service (blocklists + Tranco allow-list)."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from triage_connectors.base import HttpConnector
from triage_connectors.types import EnrichmentResult, Indicator, IndicatorType, Verdict


class LocalThreatIntelConnector(HttpConnector):
    name = "local_ti"
    supported_types = frozenset({IndicatorType.ipv4, IndicatorType.ipv6, IndicatorType.domain, IndicatorType.url})
    default_base_url = "http://localhost:8001"

    def __init__(self, **kw: Any):
        kw.setdefault("ttl", 300.0)  # local lists reload often; keep the cache short
        kw.setdefault("unknown_ttl", 300.0)
        super().__init__(**kw)

    def build_request(self, indicator: Indicator) -> httpx.Request:
        return self.client.build_request(
            "GET", f"{self.base_url}/v1/indicators/{indicator.type}/{quote(indicator.value, safe='')}"
        )

    def parse(self, indicator: Indicator, payload: dict[str, Any]) -> EnrichmentResult:
        sources = payload.get("sources", [])
        return EnrichmentResult(
            connector=self.name,
            indicator=indicator,
            verdict=Verdict(payload["verdict"]),
            score=payload.get("score"),
            summary=payload.get("summary") or ", ".join(s["source"] for s in sources),
            tags=tuple(sorted({s.get("category") or s["source"] for s in sources})),
            raw=payload,
        )
