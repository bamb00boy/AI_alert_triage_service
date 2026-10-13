"""Offline transport that answers HTTP requests from recorded JSON files.

Layout:  <root>/<host>/<path>[/<query>].json
         <root>/<host>/_default.json        (used when no specific file exists)

Each file is {"status": 200, "headers": {...}, "body": {...}}. A file with status 429
or 503 lets tests and demos exercise the retry and rate-limit paths without the network.
The adapters run their real request-building and parsing code against these responses.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx

_UNSAFE = re.compile(r"[^A-Za-z0-9._=@-]")


def fixture_path(root: Path, request: httpx.URL | httpx.Request, ignore_params: tuple[str, ...] = ()) -> Path:
    url = request.url if isinstance(request, httpx.Request) else request
    parts = [p for p in url.path.split("/") if p]
    params = sorted((k, v) for k, v in url.params.multi_items() if k not in ignore_params)
    if params:
        parts.append("&".join(f"{k}={v}" for k, v in params))
    safe = [_UNSAFE.sub("_", p) for p in parts] or ["_root"]
    return root.joinpath(url.host, *safe[:-1], f"{safe[-1]}.json")


class FixtureTransport(httpx.AsyncBaseTransport):
    def __init__(self, root: str | Path, *, ignore_params: tuple[str, ...] = ("maxAgeInDays", "verbose")):
        self.root = Path(root)
        self.ignore_params = ignore_params
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = fixture_path(self.root, request, self.ignore_params)
        if not path.exists():
            path = self.root / request.url.host / "_default.json"
        if not path.exists():
            return httpx.Response(404, json={"error": "no fixture"}, request=request)
        doc = json.loads(path.read_text())
        return httpx.Response(
            doc.get("status", 200), headers=doc.get("headers", {}), json=doc.get("body", {}), request=request
        )


def write_fixture(root: str | Path, url: str, body: dict, status: int = 200, headers: dict | None = None) -> Path:
    path = fixture_path(Path(root), httpx.URL(url), ("maxAgeInDays", "verbose"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"status": status, "headers": headers or {}, "body": body}, indent=1))
    return path
