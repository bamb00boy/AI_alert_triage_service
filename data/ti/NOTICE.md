# data/ti — sources and terms

A snapshot of public threat-intelligence and popularity lists, normalised by
`scripts/build_ti_lists.py` (the build date and file checksums are in `MANIFEST.json`). The MIT license
at the repository root does not apply to this data; each source keeps its own terms.

| File / source | Origin | Terms |
|---|---|---|
| `bad_networks.csv` — `firehol_level1` | [FireHOL IP lists](https://iplists.firehol.org/) (`firehol_level1.netset`) | an aggregate of several third-party lists (e.g. Spamhaus DROP/EDROP, DShield, bogons); each list's maintainer and terms are listed on the FireHOL site |
| `bad_networks.csv` — `feodotracker` | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | abuse.ch data is published under [CC0](https://creativecommons.org/publicdomain/zero/1.0/) |
| `bad_domains.csv` — `urlhaus`, `threatfox` | [abuse.ch URLhaus](https://urlhaus.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/) | CC0 |
| `good_domains.csv` — `tranco` | [Tranco](https://tranco-list.eu/) top 10,000 | free to use; please cite V. Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation", NDSS 2019 |

The snapshot is a point-in-time copy for reproducible evaluation; it goes stale quickly and should not
be used to block traffic. Rebuild it with `scripts/fetch_data.sh` and `scripts/build_ti_lists.py`.
