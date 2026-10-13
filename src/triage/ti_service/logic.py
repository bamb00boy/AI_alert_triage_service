"""Pure verdict logic for ti-service (kept free of I/O so it is unit-testable)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

MatchKind = Literal["exact", "parent", "network"]


@dataclass(frozen=True)
class Match:
    verdict: Literal["malicious", "benign"]
    source: str
    category: str | None
    kind: MatchKind
    listed: str  # the listed domain or network that matched
    rank: int | None = None
    prefixlen: int | None = None


def domain_candidates(domain: str) -> list[str]:
    """evil.cdn.example.com -> [evil.cdn.example.com, cdn.example.com, example.com]."""
    labels = domain.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _malicious_score(m: Match) -> float:
    if m.kind == "exact":
        return 90.0
    if m.kind == "network":
        if m.prefixlen is None or m.prefixlen >= 32:
            return 90.0
        return 80.0 if m.prefixlen >= 24 else 65.0
    return 70.0  # parent-domain match: e.g. listed evil.example.com, asked about x.evil.example.com


def decide(matches: list[Match]) -> tuple[str, float | None, str]:
    """Return (verdict, score 0-100, summary). Any malicious match beats any benign one."""
    bad = [m for m in matches if m.verdict == "malicious"]
    if bad:
        top = max(bad, key=_malicious_score)
        names = sorted({m.source for m in bad})
        return "malicious", _malicious_score(top), f"listed by {', '.join(names)} ({top.kind} match on {top.listed})"
    good = [m for m in matches if m.verdict == "benign"]
    if good:
        best = min(good, key=lambda m: (m.kind != "exact", m.rank or 10**9))
        score = 5.0 if (best.rank or 10**9) <= 1000 else 15.0
        if best.kind == "parent":
            score += 10.0  # subdomains of popular sites are abused more often than the apex
        return "benign", score, f"{best.listed} is Tranco rank {best.rank} ({best.kind} match)"
    return "unknown", None, "not listed"
