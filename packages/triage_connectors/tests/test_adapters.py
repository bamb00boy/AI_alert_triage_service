"""Adapters against mocked HTTP (respx)."""

import httpx
import pytest
import respx
from conftest import DOMAIN, IP, SHA256

from triage_connectors import (
    AuthenticationError,
    ConfigurationError,
    ConnectorTimeoutError,
    Indicator,
    IndicatorType,
    InvalidResponseError,
    RateLimitedError,
    TTLCache,
    UnsupportedIndicatorError,
    UpstreamError,
    Verdict,
)
from triage_connectors.adapters import AbuseIPDBConnector, LocalThreatIntelConnector, VirusTotalConnector
from triage_connectors.adapters.virustotal import url_id

VT = "https://www.virustotal.com/api/v3"
ABUSE = "https://api.abuseipdb.com/api/v2"


def vt_body(malicious=0, suspicious=0, harmless=0, undetected=60, **attrs):
    stats = {"malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected}
    return {"data": {"id": "x", "type": "ip_address", "attributes": {"last_analysis_stats": stats, **attrs}}}


@pytest.fixture
def vt(fast_retry):
    return VirusTotalConnector("key", rate_limiter=None, retry_policy=fast_retry, cache=TTLCache())


@pytest.fixture
def abuse(fast_retry):
    return AbuseIPDBConnector("key", rate_limiter=None, retry_policy=fast_retry)


# --- VirusTotal -----------------------------------------------------------------------------


@respx.mock
async def test_vt_malicious_ip_sends_api_key(vt):
    route = respx.get(f"{VT}/ip_addresses/{IP.value}").respond(
        json=vt_body(malicious=12, harmless=5, tags=["c2"],
                     popular_threat_classification={"suggested_threat_label": "trojan.cobaltstrike"}))
    r = await vt.enrich(IP)
    assert r.verdict is Verdict.malicious
    assert r.score == pytest.approx(15.6, abs=0.1)
    assert "trojan.cobaltstrike" in r.tags
    assert route.calls.last.request.headers["x-apikey"] == "key"


@pytest.mark.parametrize(
    "stats, verdict",
    [({"malicious": 1}, Verdict.suspicious), ({"suspicious": 2}, Verdict.suspicious),
     ({"harmless": 70}, Verdict.benign), ({}, Verdict.unknown)],
)
@respx.mock
async def test_vt_verdict_thresholds(vt, stats, verdict):
    respx.get(f"{VT}/domains/{DOMAIN.value}").respond(json=vt_body(**stats))
    assert (await vt.enrich(DOMAIN)).verdict is verdict


@respx.mock
async def test_vt_url_and_hash_paths(vt):
    url = Indicator(type=IndicatorType.url, value="http://evil.example.com/a.ps1")
    respx.get(f"{VT}/urls/{url_id(url.value)}").respond(json=vt_body(malicious=4))
    respx.get(f"{VT}/files/{SHA256.value}").respond(json=vt_body(malicious=40))
    assert (await vt.enrich(url)).verdict is Verdict.malicious
    assert (await vt.enrich(SHA256)).verdict is Verdict.malicious


@respx.mock
async def test_vt_not_found_is_unknown_not_error(vt):
    respx.get(f"{VT}/files/{SHA256.value}").respond(404, json={"error": {"code": "NotFoundError"}})
    r = await vt.enrich(SHA256)
    assert r.verdict is Verdict.unknown


@respx.mock
async def test_vt_cache_prevents_second_call(vt):
    route = respx.get(f"{VT}/ip_addresses/{IP.value}").respond(json=vt_body(harmless=3))
    first = await vt.enrich(IP)
    second = await vt.enrich(IP)
    assert route.call_count == 1
    assert not first.cached and second.cached
    assert vt.stats["cache_hits"] == 1


@respx.mock
async def test_vt_retries_429_then_succeeds(vt):
    route = respx.get(f"{VT}/ip_addresses/{IP.value}").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json=vt_body())]
    )
    await vt.enrich(IP)
    assert route.call_count == 2
    assert vt.stats["retries"] == 1


@respx.mock
async def test_vt_persistent_5xx_raises_typed_error(vt):
    route = respx.get(f"{VT}/ip_addresses/{IP.value}").respond(503)
    with pytest.raises(UpstreamError) as exc:
        await vt.enrich(IP)
    assert exc.value.retryable and exc.value.status == 503
    assert route.call_count == 3


@respx.mock
async def test_vt_auth_error_not_retried(vt):
    route = respx.get(f"{VT}/ip_addresses/{IP.value}").respond(401)
    with pytest.raises(AuthenticationError):
        await vt.enrich(IP)
    assert route.call_count == 1


@respx.mock
async def test_vt_timeout_maps_to_typed_error(vt):
    respx.get(f"{VT}/ip_addresses/{IP.value}").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(ConnectorTimeoutError):
        await vt.enrich(IP)


@respx.mock
async def test_vt_malformed_response(vt):
    respx.get(f"{VT}/ip_addresses/{IP.value}").respond(json={"unexpected": True})
    with pytest.raises(InvalidResponseError):
        await vt.enrich(IP)


def test_vt_requires_key():
    with pytest.raises(ConfigurationError):
        VirusTotalConnector(api_key=None)


# --- AbuseIPDB ------------------------------------------------------------------------------


def abuse_body(score, reports=10, whitelisted=False):
    return {"data": {"ipAddress": IP.value, "abuseConfidenceScore": score, "totalReports": reports,
                     "isWhitelisted": whitelisted, "countryCode": "NL", "usageType": "Data Center/Web Hosting/Transit",
                     "isp": "Example Hosting"}}


@pytest.mark.parametrize(
    "body, verdict",
    [(abuse_body(100), Verdict.malicious), (abuse_body(40), Verdict.suspicious),
     (abuse_body(0, reports=0), Verdict.unknown), (abuse_body(3, reports=1), Verdict.benign),
     (abuse_body(90, whitelisted=True), Verdict.benign)],
)
@respx.mock
async def test_abuseipdb_thresholds(abuse, body, verdict):
    route = respx.get(f"{ABUSE}/check").respond(json=body)
    r = await abuse.enrich(IP)
    assert r.verdict is verdict
    req = route.calls.last.request
    assert req.url.params["ipAddress"] == IP.value
    assert req.headers["Key"] == "key"


async def test_abuseipdb_rejects_domains(abuse):
    with pytest.raises(UnsupportedIndicatorError):
        await abuse.enrich(DOMAIN)


@respx.mock
async def test_abuseipdb_long_retry_after_is_not_waited(abuse):
    respx.get(f"{ABUSE}/check").respond(429, headers={"Retry-After": "3600"})
    with pytest.raises(RateLimitedError) as exc:
        await abuse.enrich(IP)
    assert exc.value.retry_after == 3600


# --- local TI ------------------------------------------------------------------------------


@respx.mock
async def test_local_ti_parses_sources(fast_retry):
    respx.get(f"http://ti:8001/v1/indicators/domain/{DOMAIN.value}").respond(json={
        "indicator": DOMAIN.value, "type": "domain", "verdict": "malicious", "score": 90,
        "sources": [{"source": "urlhaus", "category": "malware_download"}, {"source": "threatfox", "category": "c2"}],
    })
    async with LocalThreatIntelConnector(base_url="http://ti:8001", retry_policy=fast_retry) as ti:
        r = await ti.enrich(DOMAIN)
    assert r.verdict is Verdict.malicious
    assert r.tags == ("c2", "malware_download")
