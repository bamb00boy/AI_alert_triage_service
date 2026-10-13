"""Typed inputs and outputs shared by every connector."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IndicatorType(StrEnum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"


class Verdict(StrEnum):
    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"
    unknown = "unknown"


_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LEN = {IndicatorType.md5: 32, IndicatorType.sha1: 40, IndicatorType.sha256: 64}


class Indicator(BaseModel):
    """A normalised, validated observable. Construction fails on malformed values."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def _normalise(self) -> Indicator:
        v = self.value.strip()
        t = self.type
        if t in (IndicatorType.ipv4, IndicatorType.ipv6):
            ip = ipaddress.ip_address(v)
            if (t is IndicatorType.ipv4) != (ip.version == 4):
                raise ValueError(f"{v} is not {t}")
            v = str(ip)
        elif t is IndicatorType.domain:
            v = v.rstrip(".").lower()
            if "." not in v or " " in v or len(v) > 253:
                raise ValueError(f"invalid domain {v!r}")
        elif t in _HASH_LEN:
            v = v.lower()
            if len(v) != _HASH_LEN[t] or not _HEX.match(v):
                raise ValueError(f"invalid {t} {v!r}")
        object.__setattr__(self, "value", v)
        return self

    def __str__(self) -> str:
        return f"{self.type}:{self.value}"


class EnrichmentResult(BaseModel):
    """What a connector learned about one indicator."""

    model_config = ConfigDict(frozen=True)

    connector: str
    indicator: Indicator
    verdict: Verdict
    score: float | None = Field(default=None, ge=0, le=100, description="0 = benign ... 100 = certainly malicious")
    summary: str = ""
    tags: tuple[str, ...] = ()
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    cached: bool = False
    raw: dict[str, Any] | None = Field(default=None, repr=False, exclude=True)
