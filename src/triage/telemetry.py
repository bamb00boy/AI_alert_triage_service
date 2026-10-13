"""OpenTelemetry + logging setup shared by every service.

Traces are exported over OTLP/HTTP to Jaeger. Context crosses RabbitMQ through W3C
`traceparent` headers on each message (see `inject_headers` / `extract_context`), so a
single trace covers webhook -> queue -> worker -> LLM -> database.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_configured = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        span = trace.get_current_span().get_span_context()
        doc: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if span.is_valid:
            doc["trace_id"] = format(span.trace_id, "032x")
            doc["span_id"] = format(span.span_id, "016x")
        extra = getattr(record, "fields", None)
        if extra:
            doc.update(extra)
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)


def setup_telemetry(service_name: str, otlp_endpoint: str | None, log_level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    _configured = True

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(log_level)
    for noisy in ("aiormq", "aio_pika", "httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name, "service.namespace": "triage"})
    )
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint.rstrip('/')}/v1/traces"))
        )
    trace.set_tracer_provider(provider)

    from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

    HTTPXClientInstrumentor().instrument()
    AsyncPGInstrumentor().instrument()


def shutdown_telemetry() -> None:
    provider = trace.get_tracer_provider()
    if isinstance(provider, TracerProvider):
        provider.shutdown()


def tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def inject_headers(headers: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = dict(headers or {})
    propagate.inject(headers)
    return headers


def extract_context(headers: Mapping[str, Any] | None) -> otel_context.Context:
    carrier = {k: v.decode() if isinstance(v, bytes) else str(v) for k, v in (headers or {}).items()}
    return propagate.extract(carrier)


def current_trace_id() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None


def log(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    logger.log(level, msg, extra={"fields": fields})
