"""STIX bundle (data/raw/attack/enterprise-attack.json) -> data/attack/{techniques.jsonl,revoked.json}."""

from __future__ import annotations

import argparse
from pathlib import Path

from triage.attack import build_catalog

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", type=Path, default=ROOT / "data/raw/attack/enterprise-attack.json")
    ap.add_argument("--out", type=Path, default=ROOT / "data/attack")
    args = ap.parse_args()
    catalog = build_catalog(args.stix)
    catalog.save(args.out)
    subs = sum(t.is_subtechnique for t in catalog.techniques.values())
    print(f"ATT&CK {catalog.version}: {len(catalog.techniques)} techniques ({subs} sub-techniques), "
          f"{len(catalog.revoked)} revoked mappings -> {args.out}")


if __name__ == "__main__":
    main()
