from __future__ import annotations

from typing import Protocol, runtime_checkable

from triage_connectors.types import EnrichmentResult, Indicator, IndicatorType


@runtime_checkable
class Connector(Protocol):
    """Anything that can enrich an indicator. Implementations must be safe to call concurrently."""

    name: str
    supported_types: frozenset[IndicatorType]

    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        """Return a result, or raise a `triage_connectors.errors.ConnectorError` subclass."""
        ...

    async def aclose(self) -> None: ...
