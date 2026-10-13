"""ATT&CK retrieval: bge-small embeddings in pgvector, top-k techniques per alert."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg
import numpy as np

from triage.attack import Catalog
from triage.schemas import Alert, Candidate

QUERY_PREFIX = "Represent this sentence for searching relevant passages: "  # bge v1.5 query instruction


class Embedder:
    def __init__(self, model: str, cache_dir: str | None):
        cache = Path(cache_dir or "local/models/fastembed").resolve()
        cache.mkdir(parents=True, exist_ok=True)
        # Keep Hugging Face's own caches (xet chunks, tokens) inside the same directory.
        os.environ.setdefault("HF_HOME", str(cache / "hf"))
        os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        from fastembed import TextEmbedding

        self.model_name = model
        self._model = TextEmbedding(model_name=model, cache_dir=str(cache))
        self._lock = asyncio.Lock()

    def embed(self, texts: list[str]) -> np.ndarray:
        return np.array(list(self._model.embed(texts)), dtype=np.float32)

    async def embed_query(self, text: str) -> np.ndarray:
        async with self._lock:  # onnxruntime session is not re-entrant across threads
            return (await asyncio.to_thread(self.embed, [QUERY_PREFIX + text]))[0]


def alert_query_text(alert: Alert, limit: int = 1500) -> str:
    """What we search ATT&CK with: the behaviour, not the bookkeeping fields."""
    parts = [alert.rule_title]
    if alert.description:
        parts.append(alert.description)
    if alert.process:
        p = alert.process
        parts += [x for x in (p.image, p.command_line, p.parent_image) if x]
    if alert.network:
        n = alert.network
        parts.append(f"network connection to {n.dst_hostname or n.dst_ip or ''} port {n.dst_port or ''}")
    if alert.file and alert.file.path:
        parts.append(alert.file.path)
    parts += [f"{k}: {v}" for k, v in list(alert.details.items())[:12]]
    return " | ".join(parts)[:limit]


class PgVectorRetriever:
    def __init__(self, pool: asyncpg.Pool, embedder: Embedder):
        self.pool, self.embedder = pool, embedder

    async def retrieve(self, alert: Alert, k: int) -> list[Candidate]:
        vec = await self.embedder.embed_query(alert_query_text(alert))
        rows = await self.pool.fetch(
            """SELECT technique_id, name, tactics, summary, 1 - (embedding <=> $1) AS score
               FROM attack_techniques ORDER BY embedding <=> $1 LIMIT $2""",
            vec, k,
        )
        return [
            Candidate(technique_id=r["technique_id"], name=r["name"], tactics=list(r["tactics"]),
                      score=round(float(r["score"]), 4), summary=r["summary"])
            for r in rows
        ]


async def load_attack(pool: asyncpg.Pool, catalog: Catalog, embedder: Embedder, batch: int = 64) -> int:
    """(Re)load every technique chunk and its embedding."""
    techniques = sorted(catalog.techniques.values(), key=lambda t: t.id)
    rows = []
    for i in range(0, len(techniques), batch):
        chunk = techniques[i : i + batch]
        vectors = embedder.embed([t.chunk() for t in chunk])
        rows += [
            (t.id, t.full_name, list(t.tactics), t.is_subtechnique, t.summary(), t.chunk(), v,
             catalog.version, embedder.model_name)
            for t, v in zip(chunk, vectors, strict=True)
        ]
    async with pool.acquire() as conn, conn.transaction():
        await conn.execute("DELETE FROM attack_techniques")
        await conn.copy_records_to_table(
            "attack_techniques", records=rows,
            columns=["technique_id", "name", "tactics", "is_subtechnique", "summary", "chunk", "embedding",
                     "attack_version", "embed_model"],
        )
    return len(rows)
