"""ingest-api: HMAC-verified webhook -> Postgres (dedupe) -> RabbitMQ (publisher confirms)."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

import aio_pika
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from triage import hmac_auth
from triage.config import Settings, get_settings
from triage.db import create_pool
from triage.mq import ROUTING_KEY, build_message, declare_topology
from triage.normalize import NormalizationError, normalize
from triage.telemetry import current_trace_id, inject_headers, log, setup_telemetry, shutdown_telemetry

logger = logging.getLogger("triage.ingest")
tracer = trace.get_tracer("triage.ingest")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    app.state.pool = await create_pool(settings.database_url, max_size=10)
    app.state.amqp = await aio_pika.connect_robust(settings.amqp_url)
    app.state.channel = await app.state.amqp.channel(publisher_confirms=True, on_return_raises=True)
    app.state.topology = await declare_topology(
        app.state.channel, delivery_limit=settings.delivery_limit, retry_delays=settings.retry_delays_seconds
    )
    yield
    await app.state.amqp.close()
    await app.state.pool.close()
    shutdown_telemetry()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_telemetry("ingest-api", settings.otlp_endpoint, settings.log_level)
    app = FastAPI(title="triage ingest-api", lifespan=lifespan)
    app.state.settings = settings
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz(request: Request) -> dict[str, str]:
        await request.app.state.pool.fetchval("SELECT 1")
        if request.app.state.amqp.is_closed:
            raise HTTPException(503, "amqp disconnected")
        return {"status": "ready"}

    @app.post("/alerts", status_code=202)
    async def ingest_alert(
        request: Request, fmt: str = Query("generic", alias="format", pattern="^(generic|hayabusa)$")
    ) -> JSONResponse:
        body = await _read_bounded(request, settings.max_body_bytes)
        try:
            hmac_auth.verify(
                settings.hmac_secret_list(),
                body,
                request.headers.get(hmac_auth.TIMESTAMP_HEADER),
                request.headers.get(hmac_auth.SIGNATURE_HEADER),
                max_skew=settings.hmac_max_skew_seconds,
            )
        except hmac_auth.SignatureError as exc:
            log(logger, logging.WARNING, "rejected unsigned/invalid webhook", reason=str(exc),
                client=request.client.host if request.client else None)
            raise HTTPException(401, "invalid signature") from exc

        try:
            payload: Any = json.loads(body)
            alert = normalize(payload, fmt)
        except (json.JSONDecodeError, NormalizationError) as exc:
            raise HTTPException(422, f"invalid alert: {exc}") from exc

        span = trace.get_current_span()
        span.set_attribute("triage.alert_id", alert.alert_id)
        span.set_attribute("triage.rule_title", alert.rule_title)

        pool = request.app.state.pool
        row = await pool.fetchrow(
            """INSERT INTO alerts (alert_id, source, alert, raw) VALUES ($1, $2, $3, $4)
               ON CONFLICT (alert_id) DO UPDATE SET alert_id = EXCLUDED.alert_id
               RETURNING queued_at, (xmax = 0) AS inserted""",
            alert.alert_id, alert.source, alert.model_dump(mode="json"), payload,
        )
        if row["queued_at"] is not None:
            span.set_attribute("triage.duplicate", True)
            return JSONResponse({"alert_id": alert.alert_id, "status": "duplicate"}, status_code=200)

        with tracer.start_as_current_span("rabbitmq.publish", kind=trace.SpanKind.PRODUCER) as pub:
            pub.set_attribute("messaging.system", "rabbitmq")
            pub.set_attribute("messaging.destination.name", request.app.state.topology.alerts.name)
            message = build_message(
                alert.model_dump_json().encode(), message_id=alert.alert_id, headers=inject_headers()
            )
            await request.app.state.topology.alerts.publish(message, routing_key=ROUTING_KEY, mandatory=True)
        await pool.execute("UPDATE alerts SET queued_at = now() WHERE alert_id = $1", alert.alert_id)
        await pool.execute(
            "SELECT audit_append('ingest-api', 'alert.received', 'alert', $1, $2, $3)",
            alert.alert_id,
            {"rule_title": alert.rule_title, "severity": alert.severity, "observables": len(alert.observables)},
            current_trace_id(),
        )
        log(logger, logging.INFO, "alert queued", alert_id=alert.alert_id, new=row["inserted"])
        return JSONResponse({"alert_id": alert.alert_id, "status": "queued"}, status_code=202)

    return app


async def _read_bounded(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, "payload too large")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, "payload too large")
        chunks.append(chunk)
    return b"".join(chunks)
