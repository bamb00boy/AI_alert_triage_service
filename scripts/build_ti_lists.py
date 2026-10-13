"""Turn the raw feeds in data/raw/ into the normalised snapshot ti-service loads (data/ti/).

The snapshot is committed so the dataset's injected indicators stay resolvable even after
the upstream feeds rotate. Re-run after scripts/fetch_data.sh to refresh it.

    python scripts/build_ti_lists.py --good-top 10000
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "ti"
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def _lines(path: Path):
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def bad_networks() -> list[tuple[str, str, str]]:
    rows: dict[tuple[str, str], str] = {}
    dropped = 0
    for line in _lines(RAW / "firehol" / "firehol_level1.netset"):
        net = ipaddress.ip_network(line, strict=False)
        # level1 bundles bogons (10/8, 192.168/16, ...). Private space must never look malicious.
        if not net.is_global or net.prefixlen < 8:
            dropped += 1
            continue
        rows[(str(net), "firehol_level1")] = "attacks_abuse"
    for line in _lines(RAW / "feodo" / "ipblocklist.txt"):
        ip = ipaddress.ip_address(line.split(",")[0])
        if ip.is_global:
            rows[(f"{ip}/32", "feodotracker")] = "botnet_c2"
    print(f"bad networks: {len(rows)} kept, {dropped} non-global/oversized dropped")
    return sorted((n, s, c) for (n, s), c in rows.items())


def bad_domains() -> list[tuple[str, str, str]]:
    rows: dict[tuple[str, str], str] = {}
    for source, category in (("urlhaus", "malware_download"), ("threatfox", "ioc")):
        for line in _lines(RAW / source / "hostfile.txt"):
            parts = line.split()
            dom = parts[-1].lower().rstrip(".")
            if _DOMAIN.match(dom):
                rows[(dom, source)] = category
    print(f"bad domains: {len(rows)}")
    return sorted((d, s, c) for (d, s), c in rows.items())


def good_domains(top: int) -> list[tuple[str, int, str]]:
    rows = []
    with (RAW / "tranco" / "top-1m.csv").open() as fh:
        for rank_s, dom in csv.reader(fh):
            rank = int(rank_s)
            if rank > top:
                break
            rows.append((dom.lower(), rank, "tranco"))
    print(f"good domains: {len(rows)}")
    return rows


def _write(path: Path, header: list[str], rows) -> str:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--good-top", type=int, default=10_000)
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    files = {
        "bad_networks.csv": _write(OUT / "bad_networks.csv", ["network", "source", "category"], bad_networks()),
        "bad_domains.csv": _write(OUT / "bad_domains.csv", ["domain", "source", "category"], bad_domains()),
        "good_domains.csv": _write(OUT / "good_domains.csv", ["domain", "rank", "source"], good_domains(args.good_top)),
    }
    manifest = {
        "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sources": {
            "firehol_level1": "https://github.com/firehol/blocklist-ipsets (firehol_level1.netset)",
            "feodotracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
            "threatfox": "https://threatfox.abuse.ch/downloads/hostfile/",
            "tranco": f"https://tranco-list.eu/ (top {args.good_top})",
        },
        "files": files,
        "version": hashlib.sha256("".join(sorted(files.values())).encode()).hexdigest()[:16],
    }
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {OUT} (version {manifest['version']})")


if __name__ == "__main__":
    main()
