"""Fan-out runner and the offline fixture transport."""

import asyncio

from conftest import DOMAIN, IP

from triage_connectors import (
    ConnectorTimeoutError,
    EnrichmentResult,
    EnrichmentRunner,
    FixtureTransport,
    IndicatorType,
    UpstreamError,
    Verdict,
    aggregate,
)
from triage_connectors.adapters import AbuseIPDBConnector, VirusTotalConnector
from triage_connectors.fixtures import write_fixture


class Stub:
    def __init__(self, name, types, verdict=Verdict.benign, error=None, delay=0.0):
        self.name, self.supported_types = name, frozenset(types)
        self.verdict, self.error, self.delay = verdict, error, delay
        self.seen = []

    async def enrich(self, indicator):
        self.seen.append(indicator)
        await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return EnrichmentResult(connector=self.name, indicator=indicator, verdict=self.verdict)

    async def aclose(self):
        pass


async def test_runner_routes_by_type_and_collects_errors():
    ip_only = Stub("ip_only", {IndicatorType.ipv4}, Verdict.malicious)
    both = Stub("both", {IndicatorType.ipv4, IndicatorType.domain}, error=UpstreamError("both", "down"))
    slow = Stub("slow", {IndicatorType.domain}, delay=1.0)
    runner = EnrichmentRunner([ip_only, both, slow], call_timeout=0.05)

    report = await runner.run([IP, DOMAIN, IP])  # duplicate IP is looked up once

    assert ip_only.seen == [IP]
    assert len(both.seen) == 2
    assert [r.connector for r in report.results] == ["ip_only"]
    assert {type(e) for e in report.errors} == {UpstreamError, ConnectorTimeoutError}
    assert aggregate(report.for_indicator(IP)) is Verdict.malicious


def test_aggregate_worst_wins():
    mk = lambda v: EnrichmentResult(connector="c", indicator=IP, verdict=v)  # noqa: E731
    assert aggregate([]) is Verdict.unknown
    assert aggregate([mk(Verdict.benign), mk(Verdict.unknown)]) is Verdict.benign
    assert aggregate([mk(Verdict.benign), mk(Verdict.malicious), mk(Verdict.suspicious)]) is Verdict.malicious


async def test_fixture_transport_drives_real_adapters(tmp_path, fast_retry):
    write_fixture(tmp_path, f"https://www.virustotal.com/api/v3/ip_addresses/{IP.value}",
                  {"data": {"attributes": {"last_analysis_stats": {"malicious": 9, "harmless": 1}}}})
    write_fixture(tmp_path, "https://www.virustotal.com/api/v3/_default", {"error": {"code": "NotFoundError"}},
                  status=404)
    write_fixture(tmp_path, f"https://api.abuseipdb.com/api/v2/check?ipAddress={IP.value}",
                  {"data": {"abuseConfidenceScore": 100, "totalReports": 50}})

    transport = FixtureTransport(tmp_path)
    vt = VirusTotalConnector("fixture", transport=transport, rate_limiter=None, retry_policy=fast_retry)
    abuse = AbuseIPDBConnector("fixture", transport=transport, rate_limiter=None, retry_policy=fast_retry)

    assert (await vt.enrich(IP)).verdict is Verdict.malicious
    assert (await vt.enrich(DOMAIN)).verdict is Verdict.unknown  # falls back to _default (404)
    assert (await abuse.enrich(IP)).verdict is Verdict.malicious  # maxAgeInDays ignored in the path
    assert len(transport.requests) == 3
