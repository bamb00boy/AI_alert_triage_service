"""Normalise inbound payloads into the internal `Alert` schema.

Supported formats:
  * ``generic``  - `AlertIn` JSON (what the replay script sends)
  * ``hayabusa`` - one record of `hayabusa dfir-timeline -t jsonl` output
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from triage.schemas import Alert, AlertIn, FileInfo, NetworkInfo, Observable, ProcessInfo, Severity

MAX_DETAIL_KEYS = 64
MAX_DETAIL_VALUE = 4096


class NormalizationError(ValueError):
    pass


# --- identifiers -----------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_alert_id(alert_in: AlertIn) -> str:
    """Deterministic id: same source event => same id, so webhook retries dedupe."""
    if alert_in.source_ref:
        basis: Any = {"source": alert_in.source, "ref": alert_in.source_ref, "rule": alert_in.rule_id}
    else:
        basis = alert_in.model_dump(mode="json")
    return hashlib.sha256(_canonical(basis)).hexdigest()[:32]


# --- observables -----------------------------------------------------------------------

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`|]+", re.IGNORECASE)
_LABELLED_HASH = re.compile(r"\b(SHA256|SHA1|MD5)=([0-9A-Fa-f]{32,64})\b")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_NOT_TLDS = {
    "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "js", "hta", "lnk", "tmp", "log", "txt", "dat",
    "local", "lan", "internal", "corp", "home", "localdomain", "xml", "json", "ini", "evtx", "msi", "zip",
}
_HOST_FIELDS = re.compile(r"(?i)(hostname|queryname|tgthost|dst_?host|domain_?name|^domain$|^url$|query)")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _as_domain(value: str) -> str | None:
    v = value.strip().strip(".").lower()
    if not _DOMAIN.match(v):
        return None
    if v.rsplit(".", 1)[-1] in _NOT_TLDS:
        return None
    return v


def _walk_strings(obj: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def extract_observables(alert: Alert) -> list[Observable]:
    """Pull public IPs, URLs, domains and labelled file hashes out of an alert."""
    found: dict[tuple[str, str], Observable] = {}

    def add(kind: str, value: str, field: str) -> None:
        key = (kind, value)
        if key not in found:
            found[key] = Observable(type=kind, value=value, field=field)  # type: ignore[arg-type]

    doc = alert.model_dump(mode="json", exclude={"observables", "alert_id", "timestamp", "source_ref", "rule_id"})
    for field, text in _walk_strings(doc):
        for m in _IPV4.finditer(text):
            if _is_public_ip(m.group(0)):
                add("ipv4", m.group(0), field)
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;)]}")
            add("url", url, field)
            host = urlsplit(url).hostname or ""
            if _is_public_ip(host):
                add("ipv4", host, field)
            elif dom := _as_domain(host):
                add("domain", dom, field)
        for m in _LABELLED_HASH.finditer(text):
            kind, value = m.group(1).lower(), m.group(2).lower()
            if len(value) == _HASH_LEN[kind]:
                add(kind, value, field)
        leaf = field.rsplit(".", 1)[-1]
        if _HOST_FIELDS.search(leaf) and (dom := _as_domain(text)):
            add("domain", dom, field)

    if alert.file:
        for kind, value in alert.file.hashes.items():
            k = kind.lower()
            if k in _HASH_LEN and len(value) == _HASH_LEN[k]:
                add(k, value.lower(), "file.hashes")
    return list(found.values())


# --- generic -----------------------------------------------------------------------


def _bounded_details(details: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in list(details.items())[:MAX_DETAIL_KEYS]:
        if v is None or v == "" or v == "-":
            continue
        s = v if isinstance(v, str) else json.dumps(v, default=str)
        out[str(k)[:128]] = s[:MAX_DETAIL_VALUE]
    return out


def from_alert_in(alert_in: AlertIn) -> Alert:
    alert = Alert(
        alert_id=compute_alert_id(alert_in),
        **alert_in.model_dump(exclude={"details"}),
        details=_bounded_details(alert_in.details),
    )
    alert.observables = extract_observables(alert)
    return alert


# --- hayabusa -----------------------------------------------------------------------

_HAYABUSA_LEVEL = {
    "info": Severity.informational,
    "informational": Severity.informational,
    "low": Severity.low,
    "med": Severity.medium,
    "medium": Severity.medium,
    "high": Severity.high,
    "crit": Severity.critical,
    "critical": Severity.critical,
}

# Fields that carry rule-author ATT&CK labels or point at the labelled sample file.
# They are evaluation ground truth, so the normaliser never forwards them.
HAYABUSA_LABEL_FIELDS = ("MitreTactics", "MitreTags", "OtherTags", "EvtxFile", "RuleFile")

_DETAIL_CONSUMED = {
    "Proc", "Image", "Cmdline", "ParentCmdline", "PID", "User", "SrcIP", "SrcPort", "TgtIP", "TgtPort",
    "TgtHost", "Proto", "Protocol", "Hashes", "Hash", "Path",
}


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _parse_hashes(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    return {m.group(1).lower(): m.group(2).lower() for m in _LABELLED_HASH.finditer(value)}


def hayabusa_to_alert_in(rec: dict[str, Any]) -> AlertIn:
    details: dict[str, Any] = dict(rec.get("Details") or {})
    extra: dict[str, Any] = dict(rec.get("ExtraFieldInfo") or {})
    if not isinstance(rec.get("Details"), dict):
        details = {"Details": rec.get("Details")} if rec.get("Details") else {}

    level = str(rec.get("Level", "medium")).lower()
    if level not in _HAYABUSA_LEVEL:
        raise NormalizationError(f"unknown hayabusa level {level!r}")

    process = None
    if any(k in details for k in ("Proc", "Image", "Cmdline")):
        process = ProcessInfo(
            image=details.get("Proc") or details.get("Image"),
            command_line=details.get("Cmdline") or None,
            parent_image=extra.get("ParentImage"),
            parent_command_line=details.get("ParentCmdline") or None,
            pid=_int(details.get("PID")),
            user=details.get("User"),
        )
    network = None
    if any(k in details for k in ("SrcIP", "TgtIP", "TgtHost")):
        network = NetworkInfo(
            src_ip=details.get("SrcIP"),
            src_port=_int(details.get("SrcPort")),
            dst_ip=details.get("TgtIP"),
            dst_port=_int(details.get("TgtPort")),
            dst_hostname=details.get("TgtHost"),
            protocol=str(details.get("Proto") or details.get("Protocol") or "") or None,
        )
    hashes = _parse_hashes(details.get("Hashes") or details.get("Hash"))
    file = FileInfo(path=details.get("Path"), hashes=hashes) if (details.get("Path") or hashes) else None

    rest = {k: v for k, v in details.items() if k not in _DETAIL_CONSUMED and k}
    rest.update({f"extra.{k}": v for k, v in extra.items() if k not in ("ParentImage",)})

    ref_basis = f"{rec.get('EvtxFile', '')}|{rec.get('RecordID', '')}|{rec.get('RuleID', '')}|{rec.get('Timestamp')}"
    return AlertIn(
        source="hayabusa",
        source_ref=hashlib.sha256(ref_basis.encode()).hexdigest()[:24],
        rule_id=rec.get("RuleID"),
        rule_title=rec.get("RuleTitle") or "untitled",
        severity=_HAYABUSA_LEVEL[level],
        timestamp=rec["Timestamp"],
        host=rec.get("Computer"),
        user=details.get("User") or details.get("TgtUser") or details.get("SrcUser"),
        log_source=rec.get("Channel"),
        event_id=_int(rec.get("EventID")),
        process=process,
        network=network,
        file=file,
        details=rest,
    )


def normalize(payload: dict[str, Any], fmt: str = "generic") -> Alert:
    if not isinstance(payload, dict):
        raise NormalizationError("payload must be a JSON object")
    try:
        if fmt == "generic":
            alert_in = AlertIn.model_validate(payload)
        elif fmt == "hayabusa":
            alert_in = hayabusa_to_alert_in(payload)
        else:
            raise NormalizationError(f"unsupported format {fmt!r}")
    except NormalizationError:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise NormalizationError(str(exc)) from exc
    return from_alert_in(alert_in)
