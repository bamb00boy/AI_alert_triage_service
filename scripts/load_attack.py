"""Embed one chunk per ATT&CK technique with bge-small and store them in pgvector.

    python scripts/load_attack.py            # uses TRIAGE_DATABASE_URL (default: localhost)
"""

from __future__ import annotations

import asyncio
import time

from triage.attack import Catalog
from triage.config import get_settings
from triage.db import create_pool
from triage.retrieval import Embedder, load_attack


async def main() -> None:
    settings = get_settings()
    catalog = Catalog.load(settings.attack_techniques_file)
    embedder = Embedder(settings.embed_model, settings.embed_cache_dir)
    pool = await create_pool(settings.database_url)
    started = time.perf_counter()
    n = await load_attack(pool, catalog, embedder)
    await pool.close()
    print(f"embedded {n} ATT&CK {catalog.version} techniques with {settings.embed_model} "
          f"in {time.perf_counter() - started:.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
