"""Lease-based idempotency keyed by alert_id.

claim() outcomes:
  * CLAIMED - this worker owns the alert until the lease expires (renewed by LeaseKeeper)
  * DONE    - already processed; ack and drop the duplicate delivery
  * BUSY    - another live worker holds the lease; defer (retry queue) rather than drop,
              because that worker might still die before finishing.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging

import asyncpg

logger = logging.getLogger("triage.worker.idempotency")


class Claim(enum.Enum):
    CLAIMED = "claimed"
    DONE = "done"
    BUSY = "busy"


async def claim(pool: asyncpg.Pool, key: str, owner: str, lease_seconds: int) -> Claim:
    row = await pool.fetchrow(
        """INSERT INTO idempotency (key, status, owner, lease_until)
           VALUES ($1, 'processing', $2, now() + make_interval(secs => $3))
           ON CONFLICT (key) DO UPDATE
              SET status = 'processing', owner = EXCLUDED.owner, lease_until = EXCLUDED.lease_until,
                  attempts = idempotency.attempts + 1, updated_at = now()
            WHERE idempotency.status = 'dead'
               OR (idempotency.status = 'processing' AND idempotency.lease_until < now())
           RETURNING attempts""",
        key, owner, float(lease_seconds),
    )
    if row is not None:
        return Claim.CLAIMED
    status = await pool.fetchval("SELECT status FROM idempotency WHERE key = $1", key)
    return Claim.DONE if status == "done" else Claim.BUSY


async def release(pool: asyncpg.Pool, key: str, owner: str, error: str) -> None:
    """Give the lease back immediately so the scheduled retry can claim it."""
    await pool.execute(
        """UPDATE idempotency SET lease_until = now(), last_error = $3, updated_at = now()
           WHERE key = $1 AND owner = $2 AND status = 'processing'""",
        key, owner, error[:2000],
    )


async def mark_dead(pool: asyncpg.Pool, key: str, error: str) -> None:
    await pool.execute(
        """UPDATE idempotency SET status = 'dead', lease_until = NULL, last_error = $2, updated_at = now()
           WHERE key = $1 AND status <> 'done'""",
        key, error[:2000],
    )


async def mark_done(conn: asyncpg.Connection, key: str, owner: str) -> bool:
    result = await conn.execute(
        """UPDATE idempotency SET status = 'done', lease_until = NULL, updated_at = now()
           WHERE key = $1 AND owner = $2 AND status = 'processing'""",
        key, owner,
    )
    return result.endswith(" 1")


class LeaseKeeper:
    """Renews a claim every lease/3 seconds while processing is in progress."""

    def __init__(self, pool: asyncpg.Pool, key: str, owner: str, lease_seconds: int):
        self._pool, self._key, self._owner, self._lease = pool, key, owner, lease_seconds
        self._task: asyncio.Task[None] | None = None

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._lease / 3)
            try:
                await self._pool.execute(
                    """UPDATE idempotency SET lease_until = now() + make_interval(secs => $3), updated_at = now()
                       WHERE key = $1 AND owner = $2 AND status = 'processing'""",
                    self._key, self._owner, float(self._lease),
                )
            except Exception:  # renewal is best effort; the lease simply expires
                logger.warning("lease renewal failed for %s", self._key, exc_info=True)

    async def __aenter__(self) -> LeaseKeeper:
        self._task = asyncio.create_task(self._run())
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
