"""Wires the pipeline stages from settings."""

from __future__ import annotations

import asyncpg

from triage.attack import load_catalog
from triage.config import Settings
from triage.engine import TriageEngine
from triage.enrich import build_enricher
from triage.llm import build_provider
from triage.retrieval import Embedder, PgVectorRetriever
from triage.safety import SafetyGate
from triage.worker.pipeline import Pipeline


async def build_pipeline(settings: Settings, pool: asyncpg.Pool) -> Pipeline:
    names = [settings.llm_primary] + ([settings.llm_secondary] if settings.llm_secondary else [])
    engine = TriageEngine(
        providers=[build_provider(n, settings) for n in names],
        retriever=PgVectorRetriever(pool, Embedder(settings.embed_model, settings.embed_cache_dir)),
        catalog=load_catalog(str(settings.attack_techniques_file)),
        k=settings.retrieval_k,
    )
    return Pipeline(build_enricher(settings), engine, SafetyGate(settings.auto_close_min_confidence))
