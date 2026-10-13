"""Metric helpers: Wilson intervals, technique matching, calibration, latency percentiles."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class Rate:
    hits: int
    n: int
    low: float
    high: float

    @property
    def value(self) -> float | None:
        return self.hits / self.n if self.n else None

    def fmt(self) -> str:
        if not self.n:
            return "n/a"
        return f"{self.value:.1%} [{self.low:.1%}, {self.high:.1%}] (n={self.n})"

    def as_dict(self) -> dict:
        return {"value": self.value, "hits": self.hits, "n": self.n, "ci95": [self.low, self.high]}


def wilson(hits: int, n: int, z: float = 1.959964) -> Rate:
    """Wilson score interval: well-behaved for small n and for rates near 0 or 1."""
    if n == 0:
        return Rate(0, 0, 0.0, 1.0)
    p = hits / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return Rate(hits, n, max(0.0, centre - half), min(1.0, centre + half))


def technique_match(pred: str, truth: list[str]) -> bool:
    """Exact ID, or one is the parent of the other (T1059 vs T1059.001)."""
    for t in truth:
        if pred == t or pred.split(".")[0] == t or t.split(".")[0] == pred:
            return True
    return False


def calibration(confidences: list[float], correct: list[bool], bins: int = 10) -> dict:
    """Expected calibration error, Brier score and a reliability table."""
    if not confidences:
        return {"ece": None, "brier": None, "bins": []}
    c = np.clip(np.asarray(confidences, dtype=float), 0, 1)
    y = np.asarray(correct, dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(c, edges[1:-1], right=True), 0, bins - 1)
    table, ece = [], 0.0
    for b in range(bins):
        mask = idx == b
        if not mask.any():
            continue
        conf, acc, n = float(c[mask].mean()), float(y[mask].mean()), int(mask.sum())
        ece += n / len(c) * abs(acc - conf)
        table.append({"bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}", "n": n, "mean_confidence": round(conf, 3),
                      "accuracy": round(acc, 3)})
    return {"ece": round(ece, 4), "brier": round(float(np.mean((c - y) ** 2)), 4), "bins": table}


def percentiles(values: list[float]) -> dict:
    if not values:
        return {"p50": None, "p95": None, "mean": None}
    a = np.asarray(values, dtype=float)
    return {"p50": round(float(np.percentile(a, 50)), 1), "p95": round(float(np.percentile(a, 95)), 1),
            "mean": round(float(a.mean()), 1)}
