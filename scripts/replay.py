"""Feed a JSONL file of alerts into ingest-api with valid HMAC signatures.

    python scripts/replay.py data/alerts/alerts.jsonl --rate 5 --concurrency 4
    python scripts/replay.py data/alerts/alerts.jsonl --limit 10 --duplicate 0.2   # exercise dedupe
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import os
import random
import time
from pathlib import Path

import httpx

from triage.hmac_auth import sign


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", type=Path)
    ap.add_argument("--url", default=os.environ.get("TRIAGE_INGEST_URL", "http://localhost:8000"))
    ap.add_argument("--secret", default=os.environ.get("TRIAGE_HMAC_SECRETS", "dev-only-change-me").split(",")[0])
    ap.add_argument("--format", default="generic", choices=["generic", "hayabusa"])
    ap.add_argument("--rate", type=float, default=10.0, help="max requests per second")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--duplicate", type=float, default=0.0, help="fraction of alerts re-sent to test dedupe")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    lines = [ln for ln in args.file.read_text().splitlines() if ln.strip()]
    if args.limit:
        lines = lines[: args.limit]
    rng = random.Random(args.seed)
    lines += [rng.choice(lines) for _ in range(int(len(lines) * args.duplicate))]

    statuses: collections.Counter[str] = collections.Counter()
    sem = asyncio.Semaphore(args.concurrency)
    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    started = time.perf_counter()

    async with httpx.AsyncClient(base_url=args.url, timeout=30) as client:

        async def send(i: int, line: str) -> None:
            await asyncio.sleep(i * interval)
            body = json.dumps(json.loads(line), separators=(",", ":")).encode()
            async with sem:
                for attempt in range(5):
                    headers = sign(args.secret.encode(), body) | {"content-type": "application/json"}
                    try:
                        r = await client.post(f"/alerts?format={args.format}", content=body, headers=headers)
                    except httpx.TransportError as exc:
                        statuses[f"error:{type(exc).__name__}"] += 1
                        await asyncio.sleep(2**attempt)
                        continue
                    if r.status_code >= 500:
                        await asyncio.sleep(2**attempt)
                        continue
                    statuses[r.json().get("status", str(r.status_code)) if r.status_code < 300 else str(r.status_code)] += 1
                    if r.status_code >= 400:
                        print(f"line {i}: HTTP {r.status_code} {r.text[:200]}")
                    return
                statuses["gave_up"] += 1

        await asyncio.gather(*(send(i, ln) for i, ln in enumerate(lines)))

    elapsed = time.perf_counter() - started
    print(f"sent {len(lines)} alerts in {elapsed:.1f}s -> {dict(statuses)}")


if __name__ == "__main__":
    asyncio.run(main())
