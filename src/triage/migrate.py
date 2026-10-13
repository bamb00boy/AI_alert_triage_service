"""Tiny forward-only SQL migrator.

Applies migrations/NNN_*.sql in order (each in its own transaction, recorded in
schema_migrations), then re-applies migrations/grants.sql so the least-privilege
application role always matches the current schema. Runs as the schema owner.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
import time
from pathlib import Path

import asyncpg

from triage.config import get_settings

log = logging.getLogger("triage.migrate")

MIGRATIONS_DIR = Path(os.environ.get("TRIAGE_MIGRATIONS_DIR", "migrations"))


async def migrate(dsn: str, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    conn = await asyncpg.connect(dsn)
    applied_now: list[str] = []
    try:
        await conn.execute("SELECT pg_advisory_lock(hashtext('triage.migrate'))")
        await conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   name text PRIMARY KEY,
                   checksum text NOT NULL,
                   applied_at timestamptz NOT NULL DEFAULT now())"""
        )
        done = {r["name"]: r["checksum"] for r in await conn.fetch("SELECT name, checksum FROM schema_migrations")}
        for path in sorted(migrations_dir.glob("[0-9][0-9][0-9]_*.sql")):
            sql = path.read_text()
            checksum = hashlib.sha256(sql.encode()).hexdigest()
            if path.name in done:
                if done[path.name] != checksum:
                    raise RuntimeError(f"migration {path.name} was edited after being applied")
                continue
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)", path.name, checksum
                )
            applied_now.append(path.name)
            log.info("applied %s", path.name)
        grants = migrations_dir / "grants.sql"
        if grants.exists():
            await conn.execute(grants.read_text())
    finally:
        await conn.execute("SELECT pg_advisory_unlock(hashtext('triage.migrate'))")
        await conn.close()
    return applied_now


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()
    for attempt in range(30):
        try:
            applied = asyncio.run(migrate(settings.migrate_database_url))
            print(f"migrations applied: {applied or 'none (up to date)'}")
            return
        except (OSError, asyncpg.CannotConnectNowError) as exc:
            log.warning("database not ready (%s), retry %d", exc, attempt)
            time.sleep(2)
    sys.exit("database never became ready")


if __name__ == "__main__":
    main()
