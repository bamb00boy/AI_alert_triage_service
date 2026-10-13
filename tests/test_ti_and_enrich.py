import pytest

from triage.enrich import ConnectorEnricher
from triage.normalize import normalize
from triage.ti_service.logic import Match, decide, domain_candidates
from triage.worker.pipeline import TransientError
from triage_connectors import ConnectorTimeoutError, EnrichmentResult, EnrichmentRunner, IndicatorType, Verdict


def test_domain_candidates_walk_up_to_registrable():
    assert domain_candidates("a.b.Evil.com.") == ["a.b.evil.com", "b.evil.com", "evil.com"]
    assert domain_candidates("evil.com") == ["evil.com"]


def test_malicious_beats_popular():
    matches = [
        Match("benign", "tranco", "popular", "parent", "workers.dev", rank=900),
        Match("malicious", "threatfox", "ioc", "exact", "fubavy.workers.dev"),
    ]
    verdict, score, _ = decide(matches)
    assert (verdict, score) == ("malicious", 90.0)


def test_network_score_depends_on_prefix():
    assert decide([Match("malicious", "f", None, "network", "1.2.3.4/32", prefixlen=32)])[1] == 90
    assert decide([Match("malicious", "f", None, "network", "1.2.0.0/16", prefixlen=16)])[1] == 65


def test_benign_and_unknown():
    assert decide([Match("benign", "tranco", "popular", "exact", "google.com", rank=1)])[:2] == ("benign", 5.0)
    assert decide([Match("benign", "tranco", "popular", "parent", "x.com", rank=5000)])[:2] == ("benign", 25.0)
    assert decide([])[0] == "unknown"


class Stub:
    def __init__(self, name, verdict=None, error=None, types=(IndicatorType.ipv4, IndicatorType.domain,
                                                               IndicatorType.url)):
        self.name, self.supported_types, self.verdict, self.error = name, frozenset(types), verdict, error

    async def enrich(self, ind):
        if self.error:
            raise self.error
        return EnrichmentResult(connector=self.name, indicator=ind, verdict=self.verdict)

    async def aclose(self):
        pass


ALERT = normalize({
    "rule_title": "Net Conn",
    "timestamp": "2024-01-01T00:00:00Z",
    "network": {"dst_ip": "185.220.101.4", "dst_hostname": "evil.example.com"},
})


async def test_enricher_aggregates_per_indicator():
    enricher = ConnectorEnricher(
        EnrichmentRunner([Stub("local_ti", Verdict.benign), Stub("virustotal", Verdict.malicious)])
    )
    out = await enricher.enrich(ALERT)
    assert {i.value for i in out.indicators} == {"185.220.101.4", "evil.example.com"}
    assert all(i.reputation == "malicious" for i in out.indicators)
    assert out.any_malicious


async def test_optional_connector_failure_degrades():
    enricher = ConnectorEnricher(EnrichmentRunner([
        Stub("local_ti", Verdict.unknown), Stub("virustotal", error=ConnectorTimeoutError("virustotal", "slow"))]))
    out = await enricher.enrich(ALERT)
    assert out.errors and "virustotal" in out.errors[0]


async def test_required_connector_failure_is_transient():
    enricher = ConnectorEnricher(EnrichmentRunner([Stub("local_ti", error=ConnectorTimeoutError("local_ti", "x"))]))
    with pytest.raises(TransientError):
        await enricher.enrich(ALERT)
