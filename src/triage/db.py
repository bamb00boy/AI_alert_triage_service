"""asyncpg pool helpers."""

from __future__ import annotations

import json

import asyncpg


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
    await conn.set_type_codec("json", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
    has_vector = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vector')")
    if has_vector:
        from pgvector.asyncpg import register_vector

        await register_vector(conn)


async def create_pool(dsn: str, *, min_size: int = 1, max_size: int = 10) -> asyncpg.Pool:
    return await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size, init=_init_connection)
