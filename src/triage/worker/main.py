"""Competing-consumer worker: claim -> pipeline -> persist -> ack, with retry and DLQ paths."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid

import aio_pika
import asyncpg
from aio_pika.abc import AbstractIncomingMessage
from opentelemetry import trace
from pydantic import ValidationError

from triage.config import Settings, get_settings
from triage.db import create_pool
from triage.mq import ERROR_HEADER, RETRY_COUNT_HEADER, Topology, build_message, declare_topology
from triage.schemas import Alert
from triage.telemetry import (
    current_trace_id,
    extract_context,
    inject_headers,
    log,
    setup_telemetry,
    shutdown_telemetry,
)
from triage.worker import idempotency, store
from triage.worker.factory import build_pipeline
from triage.worker.pipeline import PermanentError, Pipeline, TransientError

logger = logging.getLogger("triage.worker")
tracer = trace.get_tracer("triage.worker")

TRANSIENT_EXCEPTIONS = (
    TransientError,
    asyncio.TimeoutError,
    OSError,
    asyncpg.PostgresConnectionError,
    asyncpg.InterfaceError,
)


class Worker:
    def __init__(self, settings: Settings, pool: asyncpg.Pool, topology: Topology, pipeline: Pipeline, owner: str):
        self.settings, self.pool, self.topology, self.pipeline, self.owner = (
            settings, pool, topology, pipeline, owner,
        )
        self.in_flight = 0
        self._idle = asyncio.Event()
        self._idle.set()

    async def handle(self, message: AbstractIncomingMessage) -> None:
        self.in_flight += 1
        self._idle.clear()
        try:
            await self._handle(message)
        finally:
            self.in_flight -= 1
            if self.in_flight == 0:
                self._idle.set()

    async def drain(self, timeout: float) -> None:
        try:
            await asyncio.wait_for(self._idle.wait(), timeout)
        except TimeoutError:
            logger.warning("shutdown with %d messages in flight; broker will redeliver them", self.in_flight)

    async def _handle(self, message: AbstractIncomingMessage) -> None:
        headers = dict(message.headers or {})
        ctx = extract_context(headers)
        with tracer.start_as_current_span("worker.process", context=ctx, kind=trace.SpanKind.CONSUMER) as span:
            span.set_attribute("messaging.system", "rabbitmq")
            span.set_attribute("messaging.message.id", message.message_id or "")
            span.set_attribute("messaging.rabbitmq.redelivered", bool(message.redelivered))
            span.set_attribute("triage.worker", self.owner)
            span.set_attribute("triage.delivery_count", int(headers.get("x-delivery-count", 0) or 0))
            span.set_attribute("triage.retry", int(headers.get(RETRY_COUNT_HEADER, 0) or 0))

            try:
                alert = Alert.model_validate_json(message.body)
            except ValidationError as exc:
                await self._dead_letter(message, f"invalid message: {exc.errors()[:3]}", key=None)
                return
            key = alert.alert_id
            span.set_attribute("triage.alert_id", key)

            claim = await idempotency.claim(self.pool, key, self.owner, self.settings.lease_seconds)
            span.set_attribute("triage.claim", claim.value)
            if claim is idempotency.Claim.DONE:
                log(logger, logging.INFO, "duplicate delivery dropped", alert_id=key)
                await message.ack()
                return
            if claim is idempotency.Claim.BUSY:
                await self._schedule_retry(message, "lease held by another worker")
                return

            try:
                async with idempotency.LeaseKeeper(self.pool, key, self.owner, self.settings.lease_seconds):
                    if self.settings.demo_delay_seconds:
                        await asyncio.sleep(self.settings.demo_delay_seconds)
                    out = await self.pipeline.run(alert)
                    case_id = await store.save_case(self.pool, alert, out, owner=self.owner,
                                                    trace_id=current_trace_id())
                await message.ack()
                log(logger, logging.INFO, "alert triaged", alert_id=key, case_id=case_id,
                    status=out.disposition.status, reasons=out.disposition.reasons, provider=out.result.provider)
            except PermanentError as exc:
                span.record_exception(exc)
                await idempotency.mark_dead(self.pool, key, str(exc))
                await self._dead_letter(message, str(exc), key=key)
            except TRANSIENT_EXCEPTIONS as exc:
                span.record_exception(exc)
                await _quietly(idempotency.release(self.pool, key, self.owner, repr(exc)))
                await self._schedule_retry(message, repr(exc))
            except Exception as exc:
                # Unknown failure: hand it back to the broker. Redelivery increments the quorum
                # queue's delivery count and x-delivery-limit eventually dead-letters a poison message.
                span.record_exception(exc)
                span.set_status(trace.Status(trace.StatusCode.ERROR, repr(exc)))
                logger.exception("unexpected failure on %s; requeueing", key)
                await _quietly(idempotency.release(self.pool, key, self.owner, repr(exc)))
                await message.nack(requeue=True)

    async def _schedule_retry(self, message: AbstractIncomingMessage, reason: str) -> None:
        headers = dict(message.headers or {})
        attempt = int(headers.get(RETRY_COUNT_HEADER, 0) or 0) + 1
        if attempt > len(self.topology.retry_delays):
            key = message.message_id
            if key:
                await _quietly(idempotency.mark_dead(self.pool, key, f"retries exhausted: {reason}"))
            await self._dead_letter(message, f"retries exhausted: {reason}", key=key)
            return
        headers.update(inject_headers({RETRY_COUNT_HEADER: attempt, ERROR_HEADER: reason[:500]}))
        routing_key = self.topology.retry_routing_key(attempt)
        await self.topology.retry.publish(
            build_message(message.body, message_id=message.message_id or "", headers=headers),
            routing_key=routing_key,
            mandatory=True,
        )
        await message.ack()
        trace.get_current_span().add_event("scheduled_retry", {"attempt": attempt, "queue": routing_key})
        log(logger, logging.WARNING, "scheduled retry", alert_id=message.message_id, attempt=attempt,
            queue=routing_key, reason=reason)

    async def _dead_letter(self, message: AbstractIncomingMessage, reason: str, key: str | None) -> None:
        headers = dict(message.headers or {})
        headers.update({ERROR_HEADER: reason[:1000], "x-triage-dead-by": self.owner})
        await self.topology.dead.publish(
            build_message(message.body, message_id=message.message_id or "", headers=headers), routing_key=""
        )
        await message.ack()
        await _quietly(
            self.pool.execute(
                "SELECT audit_append($1, 'alert.dead_lettered', 'alert', $2, $3, $4)",
                f"worker:{self.owner}", key or (message.message_id or "unknown"), {"reason": reason[:1000]},
                current_trace_id(),
            )
        )
        log(logger, logging.ERROR, "dead-lettered", alert_id=key, reason=reason)


async def _quietly(coro) -> None:
    try:
        await coro
    except Exception:
        logger.warning("best-effort bookkeeping failed", exc_info=True)


async def run() -> None:
    settings = get_settings()
    setup_telemetry("worker", settings.otlp_endpoint, settings.log_level)
    owner = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"

    pool = await create_pool(settings.database_url, max_size=5)
    connection = await aio_pika.connect_robust(settings.amqp_url)
    channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
    await channel.set_qos(prefetch_count=settings.prefetch)
    topology = await declare_topology(
        channel, delivery_limit=settings.delivery_limit, retry_delays=settings.retry_delays_seconds
    )
    pipeline = await build_pipeline(settings, pool)
    worker = Worker(settings, pool, topology, pipeline, owner)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    tag = await topology.queue.consume(worker.handle)
    log(logger, logging.INFO, "worker consuming", owner=owner, prefetch=settings.prefetch)
    await stop.wait()

    log(logger, logging.INFO, "shutting down", in_flight=worker.in_flight)
    await topology.queue.cancel(tag)
    await worker.drain(timeout=30)
    await connection.close()
    await pool.close()
    shutdown_telemetry()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
