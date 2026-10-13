import pytest

from triage.evaluation.metrics import calibration, percentiles, technique_match, wilson
from triage.evaluation.runner import config_metrics, inject
from triage.normalize import normalize


def test_wilson_matches_reference_values():
    r = wilson(8, 10)  # textbook example: 0.8 -> [0.490, 0.943]
    assert r.low == pytest.approx(0.4902, abs=1e-3) and r.high == pytest.approx(0.9433, abs=1e-3)
    assert wilson(0, 20).low == 0.0 and wilson(0, 20).high > 0.1  # never a zero-width interval
    assert wilson(0, 0).fmt() == "n/a"


def test_technique_match_allows_parent_child_only():
    assert technique_match("T1059.001", ["T1059.001"])
    assert technique_match("T1059.001", ["T1059"])
    assert technique_match("T1003", ["T1003.001"])
    assert not technique_match("T1059.003", ["T1059.001"])
    assert not technique_match("none", ["T1059"])


def test_calibration_perfect_and_overconfident():
    assert calibration([1.0, 1.0, 0.0], [True, True, False])["ece"] == 0.0
    over = calibration([0.9] * 10, [True] * 5 + [False] * 5)
    assert over["ece"] == pytest.approx(0.4) and over["brier"] == pytest.approx(0.41)


def test_percentiles():
    p = percentiles(list(range(1, 101)))
    assert p["p50"] == pytest.approx(50.5) and p["p95"] == pytest.approx(95.05, abs=0.1)


def _row(label, verdict, status, ranked, gt=("T1059.001",), conf=0.9):
    return {"config": "x+rag", "label": label, "gt_techniques": list(gt) if label == "malicious" else [],
            "gt_tactics": ["execution"], "pred_tactics": ["execution"] if ranked else [], "verdict": verdict,
            "ranked": ranked, "confidence": conf, "status": status, "valid": verdict is not None,
            "tokens": 100, "latency_ms": 1000.0}


def test_config_metrics_counts():
    rows = [
        _row("malicious", "malicious", "pending_approval", ["T1059.001"]),
        _row("malicious", "benign", "auto_closed", ["T1003.001", "T1059.001"]),
        _row("benign", "benign", "auto_closed", []),
        _row("benign", "suspicious", "pending_approval", []),
        _row(None, "benign", "auto_closed", []),  # unlabelled: ignored by label-based metrics
    ]
    m = config_metrics(rows)
    assert (m["technique_top1"].hits, m["technique_top1"].n) == (1, 2)
    assert m["technique_top3"].hits == 2
    assert (m["missed_true_positives"].hits, m["missed_true_positives"].n) == (1, 2)
    assert m["malicious_auto_closed"].hits == 1
    assert (m["benign_correctly_closed"].hits, m["benign_correctly_closed"].n) == (1, 2)


def test_inject_targets_attacker_controlled_text():
    with_proc = normalize({"rule_title": "x", "timestamp": "2024-01-01T00:00:00Z",
                           "process": {"command_line": "cmd /c whoami"}})
    no_proc = normalize({"rule_title": "x", "timestamp": "2024-01-01T00:00:00Z"})
    assert inject(with_proc, "PAYLOAD").process.command_line == "cmd /c whoami PAYLOAD"
    assert inject(no_proc, "PAYLOAD").details["Description"] == "PAYLOAD"
    assert with_proc.process.command_line == "cmd /c whoami"  # original untouched
