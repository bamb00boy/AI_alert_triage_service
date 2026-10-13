"""Day 0: Hayabusa detections over EVTX-ATTACK-SAMPLES -> evaluation dataset.

Outputs (data/alerts/):
  alerts.jsonl        model inputs: ATT&CK tags, sample/rule file names and technique IDs removed
  ground_truth.jsonl  labels: Sigma tags for the malicious set; rule-based labels (docs/labelling_rules.md)
                      for the info-level candidates

    python scripts/build_dataset.py
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import random
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from triage.attack import Catalog
from triage.normalize import hayabusa_to_alert_in, normalize

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
DETECTIONS = ROOT / "data" / "work" / "hayabusa" / "detections.jsonl"
OUT = ROOT / "data" / "alerts"

TECH_ID = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
URL_HOST = re.compile(r"(?i)\b(https?://)([^/\s\"':]+)")

# --- automated labelling of the info-level candidates (docs/labelling_rules.md) -------------
ATTACK_TOOLING = re.compile(
    r"(?i)psexe|mimikatz|kekeo|rubeus|potato|keefarce|herpaderp|atomicredteam|privesc|exploit|spoolfool"
    r"|invoke-|iex\s*\(|\s-enc(odedcommand)?\s|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)"
    r"|portproxy|netsh\s+i(nterface)?\s+p(ortproxy)?\s+a(dd)?\s|comsvcs|procdump|vssadmin\s+delete"
)
STRING_JOIN = re.compile(r"['\"]\s*\+\s*['\"]")  # 'ne'+'w-'+'item': 4+ joins = obfuscated script
USER_WRITABLE = re.compile(
    r"(?i)\\(users|temp|tmp|downloads|desktop|appdata|programdata|perflogs)\\|\.(rar|zip|7z)\\|^c:\\temp\\")
SYSTEM_PATH = re.compile(r"(?i)^(c:\\windows\\|\\device\\harddiskvolume\d+\\windows\\|c:\\program files)")
SYSTEM32 = re.compile(r"(?i)\\windows\\(system32|syswow64)\\")
CORE_BINARIES = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe"}
ADMIN_TOOLS = re.compile(r"(?i)\\sysmon(64)?\.exe")
ROUTINE_EVENTS = {"Logon (System) - Bootup", "Logoff", "Signed Driver Loaded", "Sysmon Service State Changed",
                  "Sysmon Config Change"}


def auto_label(alert, rule_title: str) -> tuple[str, str]:
    """Return (label, reason): label is malicious, benign or exclude. First matching rule wins."""
    text = alert.model_dump_json()
    if m := ATTACK_TOOLING.search(text):
        return "malicious", f"attack tooling: {m.group(0).strip()[:40]}"
    if len(STRING_JOIN.findall(text)) >= 4:
        return "malicious", "obfuscated script (string concatenation)"
    p = alert.process
    image = (p.image if p else None) or ""
    name = image.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if name in CORE_BINARIES and not SYSTEM32.search(image):
        return "malicious", f"{name} outside System32 (masquerading)"
    paths = [x for x in (image, p.parent_image if p else None, p.command_line if p else None,
                         alert.file.path if alert.file else None) if x]
    if any(USER_WRITABLE.search(x) for x in paths) and not any(ADMIN_TOOLS.search(x) for x in paths):
        return "malicious", "executes from a user-writable path"
    if image and (SYSTEM_PATH.match(image) or image == "System"):
        return "benign", "Windows binary from a system path, no attack indicators"
    if rule_title in ROUTINE_EVENTS:
        return "benign", "routine system event"
    return "exclude", "not decidable from the event"


def run_hayabusa() -> None:
    binary = next((RAW / "hayabusa" / "bin").glob("hayabusa-*"))
    rules = RAW / "hayabusa" / "bin" / "rules"
    DETECTIONS.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [str(binary), "dfir-timeline", "-d", str(RAW / "evtx-attack-samples"), "-r", str(rules),
         "-c", str(rules / "config"), "-w", "-O", "-t", "jsonl", "-p", "super-verbose",
         "-o", str(DETECTIONS), "-q", "-N", "-C", "-Q", "-K"],
        check=True,
    )


def scrub(obj):
    """Remove technique IDs (and Sysmon technique labels) that would leak the answer."""
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items() if not (isinstance(v, str) and "technique_id=" in v)}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        return TECH_ID.sub("[id removed]", obj)
    return obj


def round_robin(groups: dict[str, list], n: int, rng: random.Random) -> list:
    keys = sorted(groups)
    for k in keys:
        rng.shuffle(groups[k])
    picked, i = [], 0
    while len(picked) < n and any(groups[k] for k in keys):
        k = keys[i % len(keys)]
        if groups[k]:
            picked.append(groups[k].pop())
        i += 1
    return picked


def load_ti():
    with (ROOT / "data/ti/bad_networks.csv").open() as fh:
        nets = [r["network"] for r in csv.DictReader(fh)]
    with (ROOT / "data/ti/bad_domains.csv").open() as fh:
        bad_domains = [r["domain"] for r in csv.DictReader(fh)]
    with (ROOT / "data/ti/good_domains.csv").open() as fh:
        good_domains = [r["domain"] for r in csv.DictReader(fh)][:2000]
    return nets, bad_domains, good_domains


def bad_ip(nets: list[str], rng: random.Random) -> str:
    net = ipaddress.ip_network(rng.choice([n for n in nets if ipaddress.ip_network(n).prefixlen >= 16]))
    if net.num_addresses <= 2:
        return str(net.network_address)
    return str(net.network_address + rng.randrange(1, net.num_addresses - 1))


def insert_iocs(alert: dict, malicious: bool, ti, rng: random.Random) -> list[dict]:
    """Bad IPs/domains into malicious alerts, Tranco domains into benign ones."""
    nets, bad_domains, good_domains = ti
    changes = []
    net = alert.get("network")
    if net and (net.get("dst_ip") or net.get("dst_hostname")):
        if malicious:
            new_ip = bad_ip(nets, rng)
            changes.append({"field": "network.dst_ip", "old": net.get("dst_ip"), "new": new_ip, "list": "firehol"})
            net["dst_ip"] = new_ip
            new_dom = rng.choice(bad_domains)
            changes.append({"field": "network.dst_hostname", "old": net.get("dst_hostname"), "new": new_dom,
                            "list": "abuse.ch"})
            net["dst_hostname"] = new_dom
        else:
            new_dom = rng.choice(good_domains)
            changes.append({"field": "network.dst_hostname", "old": net.get("dst_hostname"), "new": new_dom,
                            "list": "tranco"})
            net["dst_hostname"] = new_dom
    proc = alert.get("process") or {}
    cmd = proc.get("command_line")
    if cmd and URL_HOST.search(cmd):
        new_dom = rng.choice(bad_domains if malicious else good_domains)
        old = URL_HOST.search(cmd).group(2)
        proc["command_line"] = URL_HOST.sub(lambda m: m.group(1) + new_dom, cmd)
        changes.append({"field": "process.command_line", "old": old, "new": new_dom,
                        "list": "abuse.ch" if malicious else "tranco"})
    return changes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", type=int, default=130)
    ap.add_argument("--benign-candidates", type=int, default=60)
    ap.add_argument("--seed", type=int, default=20261012)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    if not DETECTIONS.exists():
        run_hayabusa()
    detections = [json.loads(line) for line in DETECTIONS.open()]
    catalog = Catalog.load(ROOT / "data" / "attack")
    ti = load_ti()

    malicious_groups: dict[str, list] = defaultdict(list)
    benign_groups: dict[str, list] = defaultdict(list)
    seen: set = set()
    for rec in detections:
        techniques = sorted({t for tag in rec.get("MitreTags") or [] if (t := catalog.resolve(tag))})
        sample = rec["EvtxFile"].split("evtx-attack-samples/", 1)[-1]
        folder = sample.split("/")[0]
        if techniques and rec["Level"] in ("med", "high", "crit"):
            key = (rec["EvtxFile"], rec["RuleID"])
            if key not in seen:
                seen.add(key)
                malicious_groups[folder].append((rec, techniques, sample))
        elif not rec.get("MitreTags") and rec["Level"] == "info":
            d = rec.get("Details") or {}
            key = (rec["RuleTitle"], d.get("Proc"), d.get("Cmdline"), d.get("TgtIP"))
            if key not in seen:
                seen.add(key)
                benign_groups[rec["RuleTitle"]].append((rec, [], sample))

    picked = [(r, t, s, True) for r, t, s in round_robin(malicious_groups, args.malicious, rng)]
    picked += [(r, t, s, False) for r, t, s in round_robin(benign_groups, args.benign_candidates, rng)]

    OUT.mkdir(parents=True, exist_ok=True)
    alerts, truths = [], []
    for rec, techniques, sample, is_malicious in picked:
        alert_in = scrub(hayabusa_to_alert_in(rec).model_dump(mode="json", exclude_none=True))
        injected = insert_iocs(alert_in, is_malicious, ti, rng)
        alert = normalize(alert_in)
        alerts.append(alert_in)
        label, reason = ("malicious", "Sigma ATT&CK tags") if is_malicious else auto_label(alert, rec["RuleTitle"])
        truths.append({
            "alert_id": alert.alert_id,
            "label": label,
            "label_source": "sigma_tags" if is_malicious else "rules",
            "label_reason": reason,
            "techniques": techniques,
            "tactics": sorted({tac for t in techniques for tac in catalog.tactics_for(t)}),
            "rule_title": rec["RuleTitle"],
            "level": rec["Level"],
            "sample": sample,
            "injected": injected,
        })

    with (OUT / "alerts.jsonl").open("w") as fh:
        fh.writelines(json.dumps(a, sort_keys=True) + "\n" for a in alerts)
    with (OUT / "ground_truth.jsonl").open("w") as fh:
        fh.writelines(json.dumps(t) + "\n" for t in truths)

    by = {(t["label_source"], t["label"]) for t in truths}
    counts = {f"{src}:{lab}": sum(1 for t in truths if (t["label_source"], t["label"]) == (src, lab)) for src, lab in by}
    print(f"{len(alerts)} alerts {dict(sorted(counts.items()))}; "
          f"{sum(bool(t['injected']) for t in truths)} with inserted IOCs -> {OUT}")


if __name__ == "__main__":
    main()
