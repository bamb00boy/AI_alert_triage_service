"""Persist a pipeline result: case row + audit entry + idempotency 'done', in one transaction."""

from __future__ import annotations

import asyncpg

from triage.schemas import Alert
from triage.worker import idempotency
from triage.worker.pipeline import PipelineOutput


async def save_case(
    pool: asyncpg.Pool, alert: Alert, out: PipelineOutput, *, owner: str, trace_id: str | None
) -> int | None:
    d = out.result.decision
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute(
            """INSERT INTO alerts (alert_id, source, alert) VALUES ($1, $2, $3)
               ON CONFLICT (alert_id) DO NOTHING""",
            alert.alert_id, alert.source, alert.model_dump(mode="json"),
        )
        case_id = await conn.fetchval(
            """INSERT INTO cases (alert_id, status, verdict, technique_id, tactics, recommended_action,
                                  confidence, severity, rule_title, gate_reasons, decision, enrichment,
                                  candidates, llm_attempts, provider, model, prompt_version, trace_id)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
               ON CONFLICT (alert_id) DO NOTHING
               RETURNING case_id""",
            alert.alert_id,
            out.disposition.status,
            d.verdict if d else None,
            d.technique_id if d else None,
            d.tactics if d else [],
            d.recommended_action if d else None,
            d.confidence if d else None,
            alert.severity.value,
            alert.rule_title,
            out.disposition.reasons,
            d.model_dump(mode="json") if d else None,
            out.enrichment.model_dump(mode="json"),
            [c.model_dump(mode="json") for c in out.result.candidates],
            [a.model_dump(mode="json") for a in out.result.attempts],
            out.result.provider,
            out.result.model,
            out.result.prompt_version,
            trace_id,
        )
        if case_id is not None:
            await conn.execute(
                "SELECT audit_append($1, $2, 'case', $3, $4, $5)",
                f"worker:{owner}",
                f"case.{out.disposition.status}",
                str(case_id),
                {
                    "alert_id": alert.alert_id,
                    "verdict": d.verdict if d else None,
                    "technique_id": d.technique_id if d else None,
                    "action": d.recommended_action if d else None,
                    "confidence": d.confidence if d else None,
                    "provider": out.result.provider,
                    "prompt_version": out.result.prompt_version,
                    "gate_reasons": out.disposition.reasons,
                    "fallback": len(out.result.attempts) > 1,
                    "injection_signals": out.result.injection_signals,
                },
                trace_id,
            )
        await idempotency.mark_done(conn, alert.alert_id, owner)
        return case_id
