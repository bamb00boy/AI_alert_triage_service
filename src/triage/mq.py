"""RabbitMQ topology.

    ingest ──► [triage.alerts]  ──"alert"──► (triage.alerts  quorum, x-delivery-limit)
                    ▲                                │  nack/crash > limit │ worker gives up
                    │ TTL expiry                     ▼                     ▼
          (triage.retry.<n>s quorum) ◄──[triage.retry]          [triage.dlx] ──► (triage.dead)

Two failure paths are kept separate on purpose:
  * transient errors (TI timeout, LLM down) -> worker republishes to a delay queue whose TTL
    dead-letters back to the main exchange => exponential backoff without a busy loop.
  * messages that crash the worker are redelivered by the broker; the quorum queue's
    x-delivery-limit stops a poison message from crash-looping the fleet and dead-letters it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import aio_pika
from aio_pika.abc import AbstractChannel, AbstractExchange, AbstractQueue

ALERTS_EXCHANGE = "triage.alerts"
ALERTS_QUEUE = "triage.alerts"
ROUTING_KEY = "alert"
RETRY_EXCHANGE = "triage.retry"
DEAD_EXCHANGE = "triage.dlx"
DEAD_QUEUE = "triage.dead"

RETRY_COUNT_HEADER = "x-triage-retry"
ERROR_HEADER = "x-triage-error"


def retry_queue_name(delay_s: int) -> str:
    return f"triage.retry.{delay_s}s"


@dataclass
class Topology:
    alerts: AbstractExchange
    retry: AbstractExchange
    dead: AbstractExchange
    queue: AbstractQueue
    dead_queue: AbstractQueue
    retry_delays: tuple[int, ...]

    def retry_routing_key(self, attempt: int) -> str:
        """attempt is 1-based; delays grow exponentially and cap at the last tier."""
        delay = self.retry_delays[min(attempt, len(self.retry_delays)) - 1]
        return retry_queue_name(delay)


async def declare_topology(
    channel: AbstractChannel, *, delivery_limit: int = 5, retry_delays: tuple[int, ...] = (2, 8, 32, 128)
) -> Topology:
    alerts = await channel.declare_exchange(ALERTS_EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True)
    retry = await channel.declare_exchange(RETRY_EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True)
    dead = await channel.declare_exchange(DEAD_EXCHANGE, aio_pika.ExchangeType.FANOUT, durable=True)

    dead_queue = await channel.declare_queue(DEAD_QUEUE, durable=True, arguments={"x-queue-type": "quorum"})
    await dead_queue.bind(dead)

    # at-least-once dead-lettering needs reject-publish overflow; it guarantees the broker
    # never drops a message on its way to the DLQ.
    queue_args: dict[str, Any] = {
        "x-queue-type": "quorum",
        "x-delivery-limit": delivery_limit,
        "x-dead-letter-exchange": DEAD_EXCHANGE,
        "x-dead-letter-strategy": "at-least-once",
        "x-overflow": "reject-publish",
    }
    queue = await channel.declare_queue(ALERTS_QUEUE, durable=True, arguments=queue_args)
    await queue.bind(alerts, routing_key=ROUTING_KEY)

    for delay in retry_delays:
        q = await channel.declare_queue(
            retry_queue_name(delay),
            durable=True,
            arguments={
                "x-queue-type": "quorum",
                "x-message-ttl": delay * 1000,
                "x-dead-letter-exchange": ALERTS_EXCHANGE,
                "x-dead-letter-routing-key": ROUTING_KEY,
                "x-dead-letter-strategy": "at-least-once",
                "x-overflow": "reject-publish",
            },
        )
        await q.bind(retry, routing_key=retry_queue_name(delay))

    return Topology(alerts, retry, dead, queue, dead_queue, tuple(retry_delays))


def build_message(body: bytes, *, message_id: str, headers: dict[str, Any] | None = None) -> aio_pika.Message:
    return aio_pika.Message(
        body=body,
        message_id=message_id,
        content_type="application/json",
        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        headers=headers or {},
    )
