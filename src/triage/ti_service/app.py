"""ti-service: reputation lookups over local blocklists (bad) and Tranco (good).

    GET  /v1/indicators/{type}/{value}
    POST /v1/indicators/lookup      {"indicators": [{"type": "ipv4", "value": "..."}]}
    GET  /v1/stats
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import asyncpg
from fastapi import FastAPI, HTTPException, Request
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from pydantic import BaseModel, Field

from triage.config import Settings, get_settings
from triage.db import create_pool
from triage.telemetry import setup_telemetry, shutdown_telemetry
from triage.ti_service.logic import Match, decide, domain_candidates

logger = logging.getLogger("triage.ti_service")

IndicatorKind = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]


class LookupRequest(BaseModel):
    indicators: list[dict[str, str]] = Field(max_length=100)


class Reputation(BaseModel):
    indicator: str
    type: str
    verdict: Literal["malicious", "benign", "unknown"]
    score: float | None
    summary: str
    sources: list[dict[str, Any]]


# --- loading ------------------------------------------------------------------------------


async def load_snapshot(pool: asyncpg.Pool, data_dir: Path, *, force: bool = False) -> bool:
    manifest = json.loads((data_dir / "MANIFEST.json").read_text())
    async with pool.acquire() as conn:
        current = await conn.fetchval("SELECT value->>'version' FROM ti_meta WHERE key = 'manifest'")
        if current == manifest["version"] and not force:
            logger.info("ti snapshot %s already loaded", current)
            return False
        with (data_dir / "bad_networks.csv").open() as fh:
            nets = [(ipaddress.ip_network(r["network"]), r["source"], r["category"]) for r in csv.DictReader(fh)]
        with (data_dir / "bad_domains.csv").open() as fh:
            doms = [(r["domain"], "malicious", r["source"], r["category"], None) for r in csv.DictReader(fh)]
        with (data_dir / "good_domains.csv").open() as fh:
            doms += [(r["domain"], "benign", r["source"], "popular", int(r["rank"])) for r in csv.DictReader(fh)]
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(hashtext('ti.load'))")
            await conn.execute("DELETE FROM ti_networks")
            await conn.execute("DELETE FROM ti_domains")
            await conn.copy_records_to_table("ti_networks", records=nets, columns=["network", "source", "category"])
            await conn.copy_records_to_table(
                "ti_domains", records=doms, columns=["domain", "verdict", "source", "category", "rank"]
            )
            await conn.execute(
                """INSERT INTO ti_meta (key, value) VALUES ('manifest', $1)
                   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()""",
                manifest,
            )
    logger.info("loaded ti snapshot %s: %d networks, %d domains", manifest["version"], len(nets), len(doms))
    return True


# --- lookups ------------------------------------------------------------------------------


async def lookup_ip(pool: asyncpg.Pool, ip: str) -> list[Match]:
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        return []
    rows = await pool.fetch(
        "SELECT network, source, category FROM ti_networks WHERE network >>= $1::inet", str(addr)
    )
    return [
        Match("malicious", r["source"], r["category"], "network", str(r["network"]), prefixlen=r["network"].prefixlen)
        for r in rows
    ]


async def lookup_domain(pool: asyncpg.Pool, domain: str) -> list[Match]:
    cands = domain_candidates(domain)
    rows = await pool.fetch(
        "SELECT domain, verdict, source, category, rank FROM ti_domains WHERE domain = ANY($1::text[])", cands
    )
    return [
        Match(r["verdict"], r["source"], r["category"], "exact" if r["domain"] == cands[0] else "parent",
              r["domain"], rank=r["rank"])
        for r in rows
    ]


async def reputation(pool: asyncpg.Pool, kind: str, value: str) -> Reputation:
    value = value.strip()
    try:
        if kind in ("ipv4", "ipv6"):
            matches = await lookup_ip(pool, value)
        elif kind == "domain":
            matches = await lookup_domain(pool, value)
        elif kind == "url":
            host = urlsplit(value).hostname or ""
            try:
                ipaddress.ip_address(host)
                matches = await lookup_ip(pool, host)
            except ValueError:
                matches = await lookup_domain(pool, host) if host else []
        elif kind in ("md5", "sha1", "sha256"):
            matches = []  # no hash feeds loaded locally; VirusTotal covers hashes
        else:
            raise HTTPException(400, f"unsupported indicator type {kind}")
    except ValueError as exc:
        raise HTTPException(400, f"invalid {kind}: {exc}") from exc
    verdict, score, summary = decide(matches)
    return Reputation(
        indicator=value, type=kind, verdict=verdict, score=score, summary=summary,  # type: ignore[arg-type]
        sources=[{"source": m.source, "category": m.category, "match": m.kind, "listed": m.listed, "rank": m.rank}
                 for m in matches],
    )


# --- app ----------------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    app.state.pool = await create_pool(settings.database_url, max_size=10)
    await load_snapshot(app.state.pool, Path(settings.ti_data_dir))
    yield
    await app.state.pool.close()
    shutdown_telemetry()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_telemetry("ti-service", settings.otlp_endpoint, settings.log_level)
    app = FastAPI(title="triage ti-service", lifespan=lifespan)
    app.state.settings = settings
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/indicators/{kind}/{value:path}", response_model=Reputation)
    async def get_indicator(kind: IndicatorKind, value: str, request: Request) -> Reputation:
        return await reputation(request.app.state.pool, kind, value)

    @app.post("/v1/indicators/lookup", response_model=list[Reputation])
    async def batch(body: LookupRequest, request: Request) -> list[Reputation]:
        return [await reputation(request.app.state.pool, i["type"], i["value"]) for i in body.indicators]

    @app.get("/v1/stats")
    async def stats(request: Request) -> dict[str, Any]:
        pool = request.app.state.pool
        nets = await pool.fetch("SELECT source, count(*) AS n FROM ti_networks GROUP BY 1")
        doms = await pool.fetch("SELECT source, verdict, count(*) AS n FROM ti_domains GROUP BY 1, 2")
        meta = await pool.fetchval("SELECT value FROM ti_meta WHERE key = 'manifest'")
        return {
            "networks": {r["source"]: r["n"] for r in nets},
            "domains": {f"{r['source']}:{r['verdict']}": r["n"] for r in doms},
            "snapshot": meta,
        }

    return app
