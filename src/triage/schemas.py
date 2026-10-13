"""Domain models shared by ingest, worker, UI and evaluation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}

ObservableType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]


class Observable(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: ObservableType
    value: str = Field(max_length=2048)
    field: str | None = None


class ProcessInfo(BaseModel):
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    pid: int | None = None
    user: str | None = None


class NetworkInfo(BaseModel):
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    dst_hostname: str | None = None
    protocol: str | None = None


class FileInfo(BaseModel):
    path: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)


class AlertIn(BaseModel):
    """Generic inbound webhook payload. Unknown fields are ignored (raw payload is kept)."""

    model_config = ConfigDict(extra="ignore")

    source: str = Field(default="generic", max_length=64)
    source_ref: str | None = Field(default=None, max_length=512)
    rule_id: str | None = Field(default=None, max_length=256)
    rule_title: str = Field(max_length=512)
    severity: Severity = Severity.medium
    timestamp: datetime
    host: str | None = Field(default=None, max_length=512)
    user: str | None = Field(default=None, max_length=512)
    log_source: str | None = Field(default=None, max_length=256)
    event_id: int | None = None
    description: str | None = Field(default=None, max_length=8192)
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file: FileInfo | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    """Normalised alert. This is what goes on the queue."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    source: str
    source_ref: str | None = None
    rule_id: str | None = None
    rule_title: str
    severity: Severity
    timestamp: datetime
    host: str | None = None
    user: str | None = None
    log_source: str | None = None
    event_id: int | None = None
    description: str | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file: FileInfo | None = None
    details: dict[str, str] = Field(default_factory=dict)
    observables: list[Observable] = Field(default_factory=list)


# --- enrichment ----------------------------------------------------------------------

Reputation = Literal["malicious", "suspicious", "benign", "unknown"]


class IndicatorReport(BaseModel):
    """Aggregated view of one observable across all connectors."""

    type: ObservableType
    value: str
    reputation: Reputation
    sources: list[dict[str, Any]] = Field(default_factory=list)


class Enrichment(BaseModel):
    indicators: list[IndicatorReport] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def malicious(self) -> list[IndicatorReport]:
        return [i for i in self.indicators if i.reputation == "malicious"]

    @property
    def any_malicious(self) -> bool:
        return any(i.reputation == "malicious" for i in self.indicators)


# --- triage outcome ------------------------------------------------------------------

Verdict = Literal["malicious", "suspicious", "benign"]
CaseStatus = Literal["pending_approval", "auto_closed", "approved", "rejected"]
Action = Literal["close_benign", "monitor", "escalate", "block_indicator", "disable_account", "isolate_host"]

ACTIONS: tuple[str, ...] = Action.__args__  # type: ignore[attr-defined]
# Actions that change production state. The gate never lets these run without a human.
DISRUPTIVE_ACTIONS = frozenset({"block_indicator", "disable_account", "isolate_host"})
NO_TECHNIQUE = "none"


class Candidate(BaseModel):
    """An ATT&CK technique retrieved for an alert and offered to the model."""

    technique_id: str
    name: str
    tactics: list[str]
    score: float
    summary: str = ""


class TriageDecision(BaseModel):
    """Validated model output. Tactics are derived from ATT&CK, never taken from the model."""

    verdict: Verdict
    technique_id: str
    alternative_technique_ids: list[str] = Field(default_factory=list, max_length=2)
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: Action
    rationale: str = Field(max_length=1200)
    tactics: list[str] = Field(default_factory=list)

    def ranked_techniques(self) -> list[str]:
        out = [self.technique_id, *self.alternative_technique_ids]
        return [t for i, t in enumerate(out) if t != NO_TECHNIQUE and t not in out[:i]]


class LLMAttempt(BaseModel):
    provider: str
    model: str
    ok: bool
    error: str | None = None
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached: bool = False


class TriageResult(BaseModel):
    decision: TriageDecision | None = None
    candidates: list[Candidate] = Field(default_factory=list)
    attempts: list[LLMAttempt] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    prompt_version: str = ""
    injection_signals: list[str] = Field(default_factory=list)
    redactions: int = 0

    @property
    def total_tokens(self) -> int:
        return sum(a.prompt_tokens + a.completion_tokens for a in self.attempts)

    @property
    def latency_ms(self) -> float:
        return sum(a.latency_ms for a in self.attempts)


class Disposition(BaseModel):
    status: Literal["auto_closed", "pending_approval"]
    reasons: list[str] = Field(default_factory=list)
