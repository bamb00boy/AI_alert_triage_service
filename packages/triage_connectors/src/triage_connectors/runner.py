"""Fan an indicator set out to every connector that supports it, concurrently."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from triage_connectors.errors import ConnectorError, ConnectorTimeoutError
from triage_connectors.protocol import Connector
from triage_connectors.types import EnrichmentResult, Indicator, Verdict

_RANK = {Verdict.malicious: 3, Verdict.suspicious: 2, Verdict.benign: 1, Verdict.unknown: 0}


def aggregate(results: Iterable[EnrichmentResult]) -> Verdict:
    """Worst verdict wins: one credible 'malicious' outweighs any number of 'benign'."""
    best = Verdict.unknown
    for r in results:
        if _RANK[r.verdict] > _RANK[best]:
            best = r.verdict
    return best


@dataclass
class RunReport:
    results: list[EnrichmentResult] = field(default_factory=list)
    errors: list[ConnectorError] = field(default_factory=list)

    def for_indicator(self, indicator: Indicator) -> list[EnrichmentResult]:
        return [r for r in self.results if r.indicator == indicator]


class EnrichmentRunner:
    def __init__(self, connectors: Sequence[Connector], *, call_timeout: float = 15.0, max_concurrency: int = 8):
        self.connectors = list(connectors)
        self.call_timeout = call_timeout
        self._sem = asyncio.Semaphore(max_concurrency)

    async def _one(self, connector: Connector, indicator: Indicator) -> EnrichmentResult | ConnectorError:
        async with self._sem:
            try:
                return await asyncio.wait_for(connector.enrich(indicator), self.call_timeout)
            except TimeoutError:
                return ConnectorTimeoutError(connector.name, f"no answer within {self.call_timeout}s")
            except ConnectorError as exc:
                return exc

    async def run(self, indicators: Iterable[Indicator]) -> RunReport:
        jobs = [
            self._one(c, ind)
            for ind in dict.fromkeys(indicators)  # de-duplicate, keep order
            for c in self.connectors
            if ind.type in c.supported_types
        ]
        report = RunReport()
        for item in await asyncio.gather(*jobs):
            (report.errors if isinstance(item, ConnectorError) else report.results).append(item)
        return report

    async def aclose(self) -> None:
        await asyncio.gather(*(c.aclose() for c in self.connectors), return_exceptions=True)
