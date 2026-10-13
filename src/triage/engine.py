"""Triage stage: redact -> retrieve candidates -> prompt -> provider (with fallback) -> validate."""

from __future__ import annotations

from typing import Protocol

from opentelemetry import trace

from triage.attack import Catalog
from triage.llm import LLMProvider, LLMRequest, ProviderError, ProviderTimeout
from triage.prompt import PROMPT_VERSION, alert_hash, alert_payload, build_messages, decision_schema
from triage.safety import DecisionInvalid, parse_decision, redact
from triage.schemas import Alert, Candidate, Enrichment, LLMAttempt, TriageResult

tracer = trace.get_tracer("triage.engine")


class Retriever(Protocol):
    async def retrieve(self, alert: Alert, k: int) -> list[Candidate]: ...


class TriageEngine:
    """`providers` are tried in order: the next one is used on timeout, error or invalid output."""

    def __init__(
        self,
        providers: list[LLMProvider],
        retriever: Retriever | None,
        catalog: Catalog,
        *,
        k: int = 8,
        delimit: bool = True,
        redact_secrets: bool = True,
    ):
        self.providers, self.retriever, self.catalog = providers, retriever, catalog
        self.k, self.delimit, self.redact_secrets = k, delimit, redact_secrets

    async def run(self, alert: Alert, enrichment: Enrichment, *, variant: str = "") -> TriageResult:
        payload = alert_payload(alert)
        redactions = 0
        if self.redact_secrets:
            payload, redactions = redact(payload)

        candidates: list[Candidate] = []
        if self.retriever is not None:
            with tracer.start_as_current_span("retrieve") as span:
                candidates = await self.retriever.retrieve(alert, self.k)
                span.set_attribute("triage.candidates", [c.technique_id for c in candidates])

        request = LLMRequest(
            messages=build_messages(payload, enrichment, candidates or None, delimit=self.delimit),
            schema=decision_schema([c.technique_id for c in candidates] or None),
            cache_key=f"{PROMPT_VERSION}:{alert_hash(alert)}:{variant}",
        )
        result = TriageResult(candidates=candidates, prompt_version=PROMPT_VERSION, redactions=redactions)

        for provider in self.providers:
            with tracer.start_as_current_span(f"llm.{provider.name}") as span:
                span.set_attribute("gen_ai.request.model", provider.model)
                attempt = LLMAttempt(provider=provider.name, model=provider.model, ok=False)
                try:
                    resp = await provider.generate(request)
                    attempt.latency_ms = resp.latency_ms
                    attempt.prompt_tokens, attempt.completion_tokens = resp.prompt_tokens, resp.completion_tokens
                    attempt.cached = resp.cached
                    attempt.provider, attempt.model = resp.provider, resp.model  # replay reports its source
                    span.set_attribute("gen_ai.usage.input_tokens", resp.prompt_tokens)
                    span.set_attribute("gen_ai.usage.output_tokens", resp.completion_tokens)
                    decision = parse_decision(resp.text, candidates or None, self.catalog)
                except ProviderTimeout as exc:
                    attempt.error = f"timeout: {exc}"
                except ProviderError as exc:
                    attempt.error = f"error: {exc}"
                except DecisionInvalid as exc:
                    attempt.error = f"invalid: {exc}"
                else:
                    attempt.ok = True
                    result.attempts.append(attempt)
                    result.decision, result.provider, result.model = decision, resp.provider, resp.model
                    return result
                span.set_attribute("triage.fallback_reason", attempt.error or "")
                result.attempts.append(attempt)
        return result
