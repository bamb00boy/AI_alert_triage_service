# Labelling rules

Every label is produced by `scripts/build_dataset.py`; nothing is labelled by hand, so the dataset is
reproducible from the raw downloads. The dataset (`data/alerts/`) has two kinds of alert.

## 1. Sigma-tagged alerts → `malicious` (`label_source = sigma_tags`)

Hayabusa detections at level medium/high/critical whose Sigma rule carries ATT&CK tags.

- `techniques` = the rule's ATT&CK tags, with revoked IDs mapped forward through ATT&CK's
  `revoked-by` relationships (e.g. T1086 → T1059.001). Software/group tags (S0002, G0007) are dropped.
- `tactics` = the union of those techniques' tactics in ATT&CK v19.2 (from STIX, not Hayabusa's
  abbreviations).
- One alert per (sample file, rule) pair, sampled round-robin across the dataset's tactic folders.

## 2. Info-level candidates → rule-based label (`label_source = rules`)

Untagged info-level detections (Hayabusa's generic event rules: process created, file created, pipe
connected, logon, ...). They come from attack recordings, so some are attack steps and some are
background noise. `auto_label()` applies these rules in order; the first match wins and its reason is
stored in `label_reason`:

| # | Rule | Label |
|---|---|---|
| 1 | The alert mentions attack tooling: PsExec/PSEXESVC, Mimikatz, Kekeo, Rubeus, \*Potato, KeeFarce, Herpaderping, Atomic Red Team, "privesc"/"exploit" tool names, SpoolFool, `Invoke-`, `iex(`, `-enc`, `reg save HKLM\SAM\|SECURITY\|SYSTEM`, `netsh … portproxy`, comsvcs, procdump, `vssadmin delete` | malicious |
| 2 | A PowerShell/script body with 4+ string concatenations (`'ne'+'w-'+'item'`) | malicious |
| 3 | A core Windows binary name (svchost, lsass, csrss, services, smss, winlogon, wininit) running outside System32/SysWOW64 | malicious (masquerading) |
| 4 | The process image, parent, command line or file path is in a user-writable location (`\Users\`, `\Temp\`, `\Downloads\`, `\Desktop\`, `\AppData\`, `\ProgramData\`, `C:\temp\`, inside an archive), unless it is Sysmon itself | malicious |
| 5 | The process image is a Windows binary from `C:\Windows\` or `C:\Program Files` (or the `System` process) | benign |
| 6 | Routine bookkeeping events: bootup logon, logoff, signed driver loaded, Sysmon service/config change | benign |
| 7 | Anything else (logons, Kerberos tickets, directory-service changes, scheduled tasks …) | `exclude` — not scored |

Malicious rule-labelled alerts have no technique, so they count for verdict metrics only.

With the committed data this yields 25 malicious, 17 benign and 18 excluded candidates.

## Leakage control

The model never sees: Sigma ATT&CK tags (`MitreTags`, `MitreTactics`, `OtherTags`), the sample
path or rule file name (both name the technique or tactic), Sysmon `RuleName` values of the form
`technique_id=…,technique_name=…`, or technique IDs anywhere in the event (Atomic Red Team command
lines contain paths like `atomics\T1003\`); those are replaced with `[id removed]`. The labelling rules
read only the alert the model sees, never the sample name.

## Inserted indicators

Lab captures only contain private addresses, so threat intel has nothing to say about them.
Alerts with a network destination or a URL get indicators inserted (recorded under `injected`
in `ground_truth.jsonl`):

- malicious (Sigma-tagged) alerts: destination IP from FireHOL level 1, destination/URL domain from
  abuse.ch (URLhaus, ThreatFox);
- info-level candidates: destination/URL domain from the Tranco top sites. A candidate the rules label
  malicious keeps its Tranco domain — this models an attacker using reputable infrastructure.
