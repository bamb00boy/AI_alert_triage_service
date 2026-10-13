"""Enrichment stage: alert observables -> connector SDK fan-out -> per-indicator reputation."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from triage.config import Settings
from triage.schemas import Alert, Enrichment, IndicatorReport
from triage.worker.pipeline import TransientError
from triage_connectors import (
    ConfigurationError,
    Connector,
    EnrichmentRunner,
    FixtureTransport,
    Indicator,
    RetryPolicy,
    TokenBucket,
    TTLCache,
    aggregate,
)
from triage_connectors.adapters import AbuseIPDBConnector, LocalThreatIntelConnector, VirusTotalConnector

logger = logging.getLogger("triage.enrich")

MAX_INDICATORS = 12


class ConnectorEnricher:
    """`required` connectors must answer; if one fails transiently the alert is retried later.
    Optional connectors degrade gracefully: their errors are recorded and force human review."""

    def __init__(self, runner: EnrichmentRunner, *, required: Iterable[str] = ("local_ti",)):
        self.runner = runner
        self.required = set(required)

    async def enrich(self, alert: Alert) -> Enrichment:
        indicators: list[Indicator] = []
        for obs in alert.observables:
            try:
                indicators.append(Indicator(type=obs.type, value=obs.value))
            except ValueError:
                continue
        indicators = list(dict.fromkeys(indicators))[:MAX_INDICATORS]
        if not indicators:
            return Enrichment()

        report = await self.runner.run(indicators)
        blocking = [e for e in report.errors if e.connector in self.required and e.retryable]
        if blocking:
            raise TransientError(f"required connector unavailable: {blocking[0]}")

        out = []
        for ind in indicators:
            results = report.for_indicator(ind)
            out.append(
                IndicatorReport(
                    type=ind.type.value,  # type: ignore[arg-type]
                    value=ind.value,
                    reputation=aggregate(results).value,  # type: ignore[arg-type]
                    sources=[
                        {"connector": r.connector, "verdict": r.verdict.value, "score": r.score,
                         "summary": r.summary, "tags": list(r.tags), "cached": r.cached}
                        for r in results
                    ],
                )
            )
        return Enrichment(indicators=out, errors=[str(e) for e in report.errors])

    async def aclose(self) -> None:
        await self.runner.aclose()


def build_connectors(settings: Settings) -> list[Connector]:
    cache = TTLCache(max_entries=50_000)
    retry = RetryPolicy(max_attempts=3, base_delay=0.5, max_delay=4.0)
    connectors: list[Connector] = []
    fixtures = settings.connector_mode == "fixtures"
    transport = FixtureTransport(settings.fixtures_dir) if fixtures else None
    # In fixture mode there is no real quota to respect; keep a generous bucket so the code path still runs.
    fixture_bucket = (lambda: TokenBucket(rate=200, capacity=50)) if fixtures else (lambda: None)

    for name in settings.connectors:
        try:
            if name == "local_ti":
                connectors.append(LocalThreatIntelConnector(base_url=settings.ti_url, cache=cache, retry_policy=retry))
            elif name == "virustotal":
                key = "fixture" if fixtures else (settings.virustotal_api_key or _missing("virustotal")).get_secret_value()
                kw = {"rate_limiter": fixture_bucket()} if fixtures else {}
                connectors.append(VirusTotalConnector(key, transport=transport, cache=cache, retry_policy=retry, **kw))
            elif name == "abuseipdb":
                key = "fixture" if fixtures else (settings.abuseipdb_api_key or _missing("abuseipdb")).get_secret_value()
                kw = {"rate_limiter": fixture_bucket()} if fixtures else {}
                connectors.append(AbuseIPDBConnector(key, transport=transport, cache=cache, retry_policy=retry, **kw))
            else:
                logger.warning("unknown connector %s ignored", name)
        except ConfigurationError as exc:
            logger.warning("connector disabled: %s", exc)
    return connectors


def _missing(name: str):
    raise ConfigurationError(name, f"TRIAGE_{name.upper()}_API_KEY not set (or use TRIAGE_CONNECTOR_MODE=fixtures)")


def build_enricher(settings: Settings) -> ConnectorEnricher:
    return ConnectorEnricher(EnrichmentRunner(build_connectors(settings), call_timeout=15.0))
