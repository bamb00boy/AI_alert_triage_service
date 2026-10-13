"""Redaction, output validation and the safety gate."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from triage.attack import TECHNIQUE_ID, Catalog
from triage.schemas import NO_TECHNIQUE, Alert, Candidate, Disposition, Enrichment, TriageDecision, TriageResult

# --- redaction -------------------------------------------------------------------------

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED-KEY]"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b"), "[REDACTED-JWT]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"(?i)\bbearer\s+[\w.~+/-]{16,}=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(\b(?:password|passwd|pwd|pass|secret|token|api[_-]?key)\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)(\s[-/](?:p|pw|password)[:\s]\s*)(?!\[REDACTED)(\S+)"), r"\1[REDACTED]"),  # psexec -p, /p:
    (re.compile(r"(?i)(\bnet1?(?:\.exe)?\s+user\s+\S+\s+)(?!/)(\S+)"), r"\1[REDACTED]"),  # net user NAME PASSWORD
    (re.compile(r"(?i)(://[^/\s:@]+:)[^/\s@]+@"), r"\1[REDACTED]@"),  # credentials in URLs
    (re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b"), "[REDACTED-NTLM]"),  # LM:NT hash pairs
]


def redact_text(text: str) -> tuple[str, int]:
    total = 0
    for pattern, repl in _REDACTIONS:
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def redact(obj: Any) -> tuple[Any, int]:
    """Recursively redact secrets from every string in a JSON-like structure."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out, n = {}, 0
        for k, v in obj.items():
            out[k], c = redact(v)
            n += c
        return out, n
    if isinstance(obj, list):
        items = [redact(v) for v in obj]
        return [v for v, _ in items], sum(c for _, c in items)
    return obj, 0


# --- output validation -----------------------------------------------------------------


class DecisionInvalid(ValueError):
    """Model output failed schema or policy validation. Triggers fallback."""


def parse_decision(text: str, candidates: list[Candidate] | None, catalog: Catalog) -> TriageDecision:
    try:
        raw = json.loads(text)
        decision = TriageDecision.model_validate(raw)
    except (ValueError, ValidationError) as exc:  # bad JSON, wrong types, action not on the allow-list
        raise DecisionInvalid(f"schema: {str(exc)[:300]}") from exc

    allowed = {c.technique_id for c in candidates} if candidates else None
    resolved = []
    for tid in [decision.technique_id, *decision.alternative_technique_ids]:
        if tid == NO_TECHNIQUE:
            resolved.append(tid)
            continue
        if allowed is not None and tid not in allowed:
            raise DecisionInvalid(f"technique {tid} is not one of the retrieved candidates")
        # Revoked IDs (the model's training data predates ATT&CK v19) map forward, as the ground truth does.
        current = catalog.resolve(tid) if TECHNIQUE_ID.match(tid) else None
        if current is None:
            raise DecisionInvalid(f"technique {tid} is not a current ATT&CK technique")
        resolved.append(current)
    decision.technique_id, decision.alternative_technique_ids = resolved[0], resolved[1:]
    decision.tactics = list(catalog.tactics_for(decision.technique_id))
    return decision


# --- gate -------------------------------------------------------------------------------


class SafetyGate:
    """Only a confident, consistent 'benign' is closed automatically; everything else goes to a human."""

    def __init__(self, min_confidence: float = 0.85):
        self.min_confidence = min_confidence

    def evaluate(self, alert: Alert, enrichment: Enrichment, result: TriageResult) -> Disposition:
        d = result.decision
        if d is None:
            return Disposition(status="pending_approval", reasons=["no_valid_model_decision"])
        reasons = []
        if d.verdict != "benign":
            reasons.append(f"verdict_{d.verdict}")
        if d.confidence < self.min_confidence:
            reasons.append("low_confidence")
        if enrichment.any_malicious:
            reasons.append("threat_intel_malicious")
        if d.recommended_action != "close_benign":
            reasons.append(f"action_{d.recommended_action}")
        if not reasons:
            return Disposition(status="auto_closed", reasons=["benign_high_confidence"])
        return Disposition(status="pending_approval", reasons=reasons)
