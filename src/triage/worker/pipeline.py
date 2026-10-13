"""enrich -> triage -> safety gate, each stage in its own span."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from opentelemetry import trace

from triage.schemas import Alert, Disposition, Enrichment, TriageResult

tracer = trace.get_tracer("triage.worker.pipeline")


class TransientError(Exception):
    """Retry later with backoff (dependency down, timeout, rate limited)."""


class PermanentError(Exception):
    """Retrying cannot help (malformed message). Dead-letter immediately."""


class Enricher(Protocol):
    async def enrich(self, alert: Alert) -> Enrichment: ...


class Engine(Protocol):
    async def run(self, alert: Alert, enrichment: Enrichment) -> TriageResult: ...


class Gate(Protocol):
    def evaluate(self, alert: Alert, enrichment: Enrichment, result: TriageResult) -> Disposition: ...


@dataclass
class PipelineOutput:
    enrichment: Enrichment
    result: TriageResult
    disposition: Disposition


class Pipeline:
    def __init__(self, enricher: Enricher, engine: Engine, gate: Gate):
        self.enricher, self.engine, self.gate = enricher, engine, gate

    async def run(self, alert: Alert) -> PipelineOutput:
        with tracer.start_as_current_span("stage.enrich") as span:
            enrichment = await self.enricher.enrich(alert)
            span.set_attribute("triage.indicators", len(enrichment.indicators))
            span.set_attribute("triage.ti_malicious", len(enrichment.malicious))
            if enrichment.errors:
                span.set_attribute("triage.enrichment_errors", enrichment.errors)

        with tracer.start_as_current_span("stage.triage") as span:
            result = await self.engine.run(alert, enrichment)
            if result.decision:
                span.set_attribute("triage.verdict", result.decision.verdict)
                span.set_attribute("triage.technique", result.decision.technique_id)
                span.set_attribute("triage.confidence", result.decision.confidence)
            span.set_attribute("triage.provider", result.provider or "none")

        with tracer.start_as_current_span("stage.safety_gate") as span:
            disposition = self.gate.evaluate(alert, enrichment, result)
            span.set_attribute("triage.disposition", disposition.status)
            span.set_attribute("triage.gate_reasons", disposition.reasons)

        return PipelineOutput(enrichment, result, disposition)

