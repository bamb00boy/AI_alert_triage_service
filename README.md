# AI alert triage service

[![ci](https://github.com/bamb00boy/AI_alert_triage_service/actions/workflows/ci.yml/badge.svg)](https://github.com/bamb00boy/AI_alert_triage_service/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A local-first pipeline that triages security alerts with a small local LLM, and is careful about it:
alerts arrive on an HMAC-signed webhook, are enriched with threat intel, matched against MITRE ATT&CK
by vector retrieval, classified by a model whose output is constrained and validated, and then pass a
safety gate. Only a confident, consistent "benign" closes itself; everything else waits for a human
analyst behind Keycloak. Every step is traced, and every decision lands in an append-only audit log.

Everything runs on one laptop (Docker + native Ollama/llama.cpp). The [cloud mapping](#local--cloud) shows
what each piece becomes in Azure or AWS.

## Architecture

```
            HMAC webhook
 replay.py ─────────────► ingest-api ──► Postgres (alerts, dedupe)
                              │ publish (confirms)
                              ▼
                 RabbitMQ  triage.alerts  (quorum, x-delivery-limit=5, DLX → triage.dead)
                     ▲        │  competing consumers
   retry.{2,8,32,128}s│       ▼
                 ┌────┴──────────────── worker ×2 ───────────────────────────────┐
                 │ claim (idempotency lease) → enrich → retrieve → triage → gate │
                 └──────┬───────────┬──────────────┬──────────────┬─────────────┘
                        │           │              │              │
             triage_connectors   pgvector    Ollama (A) ──fallback──► llama-server (B)
            ti-service, VT, AbuseIPDB  ATT&CK       (host, Metal GPU)
                                                                  ▼
                                   Postgres cases + append-only audit_log
                                                                  ▼
                                          approval-ui (FastAPI + HTMX) ◄── Keycloak (analyst / viewer)
          Jaeger: one trace per alert across ingest-api → RabbitMQ → worker → LLM → Postgres
```

| Service | What it does |
|---|---|
| `ingest-api` | `POST /alerts`: verifies `X-Triage-Signature` (HMAC-SHA256 over `timestamp.body`, 5-minute window, rotatable keys), normalises into the `Alert` schema, dedupes on a deterministic `alert_id`, publishes with publisher confirms. |
| `worker` ×2 | aio-pika consumer, manual acks, prefetch 1. Claims each alert with a lease in the `idempotency` table, runs the pipeline, writes case + audit + idempotency in one transaction. |
| `ti-service` | Loads FireHOL level 1, Feodo Tracker, URLhaus, ThreatFox (bad) and the Tranco top 10k (good) into Postgres; `GET /v1/indicators/{type}/{value}` returns a verdict, score and sources (IP lookups use a GiST `>>=` index over CIDRs). |
| `approval-ui` | Case queue and detail pages. Keycloak OIDC login (PKCE); `analyst` can approve, edit or reject, `viewer` can only read (enforced server-side, 403). |
| `postgres` | pgvector. Alerts, cases, idempotency, audit log, TI tables, ATT&CK vectors. |
| `rabbitmq` | Quorum queues, delivery limit, dead-letter exchange, management UI on :15672. |
| `jaeger` | OTLP traces for every stage. |
| `keycloak` | Realm `triage` with roles `analyst` and `viewer` (`docker/keycloak/realm-triage.json`). |
| host | `ollama` (Qwen3-4B-Instruct-2507, Q4_K_M) and `llama-server` (Llama-3.2-3B-Instruct, Q4_K_M), run natively for GPU access. |

### Pipeline stages

1. **Enrich** (`triage_connectors`): public IPs, domains, URLs and hashes from the alert are looked up in
   parallel. The local TI connector is required (a transient failure retries the alert later); VirusTotal
   and AbuseIPDB degrade gracefully. Worst verdict wins.
2. **Retrieve**: the alert's behaviour (rule title, process, command line, parent, network, details) is
   embedded with `bge-small-en-v1.5` and the 8 nearest ATT&CK techniques are fetched from pgvector
   (one chunk per technique: ID, name, tactics, platforms, description).
3. **Triage**: secrets are redacted, the alert is placed in a nonce-delimited untrusted block, and the
   model must answer in a JSON schema whose `technique_id` is an `enum` of exactly the retrieved
   candidates and whose `recommended_action` is an `enum` of the allow-list. The output is validated again
   in Python; tactics are looked up in ATT&CK, never taken from the model. Timeout, error or invalid output
   → the same prompt goes to the second provider.
4. **Gate**: auto-close only when verdict = benign, action = `close_benign`, confidence ≥ 0.85 and no
   indicator is known-bad. Everything else becomes `pending_approval` with the reasons listed.

## Running it

Everything — the virtualenv, datasets, model weights, runtime binaries and container state — lives
inside this repository (`venv/`, `data/raw/`, `local/`). Deleting the folder removes it all; Docker images
are the one exception (`docker compose down --rmi all -v`).

```bash
python3 -m venv venv
PIP_NO_CACHE_DIR=1 venv/bin/pip install -e "packages/triage_connectors[test]" -e ".[dev,embed]"

./scripts/install_llm_runtimes.sh      # Ollama + llama.cpp + one model each, into local/ (~5 GB)
./scripts/run_llm_runtimes.sh          # ollama :11434, llama-server :8081

docker compose up -d --build           # postgres, rabbitmq, jaeger, keycloak, ti-service, ingest-api, worker×2, approval-ui
venv/bin/python scripts/load_attack.py # embed ATT&CK v19.2 into pgvector (~90 s)

venv/bin/python scripts/replay.py data/alerts/alerts.jsonl --rate 1
```

| URL | |
|---|---|
| http://localhost:8002 | approval UI — `alice`/`alice` (analyst), `victor`/`victor` (viewer) |
| http://localhost:16686 | Jaeger |
| http://localhost:15672 | RabbitMQ (`triage`/`triage`) |

**Competing consumers and redelivery.** Start the workers slowed down, send a few alerts and kill one
worker mid-message:

```bash
TRIAGE_DEMO_DELAY_SECONDS=20 docker compose up -d worker
venv/bin/python scripts/replay.py data/alerts/alerts.jsonl --limit 4
docker kill -s KILL triage-worker-1
docker compose logs -f worker   # worker-2 receives the redelivered message, waits out the dead worker's lease, triages it once
```

Tests: `venv/bin/pytest` (service) and `cd packages/triage_connectors && ../../venv/bin/pytest` (SDK).

### Rebuilding the data

The derived data is committed so the stack and the evaluation are reproducible offline. To rebuild it:

```bash
./scripts/fetch_data.sh                          # ATT&CK STIX, EVTX-ATTACK-SAMPLES, blocklists, Tranco, Hayabusa → data/raw/
venv/bin/python scripts/build_ti_lists.py        # → data/ti/ (snapshot ti-service loads)
venv/bin/python scripts/build_attack_catalog.py  # → data/attack/ (one record per technique, revoked-ID map)
venv/bin/python scripts/build_dataset.py         # Hayabusa over the EVTX samples → data/alerts/
```

## Design decisions

- **Deterministic alert IDs, two layers of dedupe.** `alert_id` is a hash of the source event, so a
  retried webhook is a no-op at ingest (`queued_at` is only set after the broker confirms, so a crash
  between insert and publish is healed by the client's retry). Workers additionally claim alerts in an
  `idempotency` table with a lease that a background task renews; a crashed worker's lease expires and
  the redelivered message is processed exactly once (case insert, audit entry and `done` commit together).
- **Two failure paths on purpose.** Transient errors (TI down, model timeout) are republished to tiered
  delay queues (2 s, 8 s, 32 s, 128 s) whose TTL dead-letters back to the main exchange — exponential
  backoff without blocking a consumer. Messages that crash a worker are redelivered by the broker and the
  quorum queue's `x-delivery-limit` dead-letters a poison message instead of letting it crash-loop the
  fleet. Malformed messages go straight to the DLQ with the reason in a header.
- **Constrain, then validate.** The JSON schema sent to Ollama (`format`) and llama-server
  (`response_format`) makes an out-of-list technique or action impossible to *generate*; Pydantic and an
  explicit candidate check reject anything that slips through (e.g. a provider that ignores the schema).
  Either failure triggers the fallback provider.
- **ATT&CK has moved on; models have not.** Recent releases (the bundle here is v19.2) replaced Defense
  Evasion with `stealth` and `defense-impairment` and re-numbered many techniques (e.g. T1070.001 → T1685.005). Sigma tags and model answers are both mapped
  forward through `revoked-by` relationships, so neither is penalised for using an older ID.
- **One cache, three uses.** `ReplayProvider` is the evaluation cache (keyed by prompt version + alert
  hash + variant), the replay provider for tests, and CI's model: CI never calls an LLM.
- **Postgres for all state** (cases, audit, idempotency, TI, vectors): one stateful dependency to back up,
  and transactions span the case, its audit entry and the idempotency marker.
- **Least privilege in the database.** Services connect as `triage_app`, which cannot `UPDATE`, `DELETE`
  or even `INSERT` into `audit_log`; the only write path is the `SECURITY DEFINER` function
  `audit_append()`, which hash-chains each row. A trigger blocks updates and deletes even for the owner,
  and `SELECT * FROM audit_verify()` lists any row whose hash or link is wrong.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Prompt injection** — the attacker controls command lines, file names, user names in the alert | Untrusted block delimited by a per-request nonce with `<` escaped; explicit "data, not instructions" rule; constrained output (candidate and action enums); the pipeline never executes an action — the only automatic outcome is closing a confident benign alert, and that also requires no known-bad indicator; an approved action is recorded for a responder or SOAR to carry out | A small model can still be talked into a confident *benign*, which the gate cannot distinguish from a real one: with mitigations on, 62% of injected malicious alerts would be auto-closed (see Evaluation). |
| Forged or replayed webhooks | HMAC-SHA256 over timestamp + body, constant-time compare, 5-minute window, rotatable secrets; deterministic IDs make in-window replays no-ops; 256 KB body limit | Shared-secret model: a leaked secret allows forgery until rotated. |
| Secrets in alerts reaching the model or logs | Regex redaction (passwords on command lines, `net user`, URL credentials, bearer tokens, JWTs, AWS keys, private keys, NTLM hashes) before prompting | Pattern-based; novel secret formats pass through. |
| Poison messages, queue floods | Delivery limit + DLQ, bounded retries, prefetch 1, at-least-once dead-lettering | No per-source rate limit on ingest. |
| Tampering with the decision history | Append-only `audit_log` (privileges + trigger), hash chain, `audit_verify()` | A database superuser can disable triggers and rewrite the chain; ship the log to WORM storage in production. |
| Unauthorised approvals | Keycloak OIDC with PKCE, roles in the ID token, server-side role check on every POST (viewer → 403), SameSite=Lax session cookie, compare-and-set on `pending_approval` (double decisions → 409) | No step-up auth for disruptive actions. |
| XSS via alert content in the UI | Jinja2 autoescaping everywhere; alert JSON rendered as text | — |
| Threat-intel poisoning | Worst-verdict-wins aggregation; a known-bad hit blocks auto-close | A benign-listed (Tranco) domain used by an attacker does not raise the alarm by itself. |

Out of scope for the local build: TLS between services, a secrets manager (dev defaults are in
`docker-compose.yml`), multi-tenancy.

## Evaluation

**Dataset (`data/alerts/`, 190 alerts).** Hayabusa 4.1 ran the Sigma/Hayabusa rule set over
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (5,360 detections). 130
medium-to-critical detections with ATT&CK tags (one per sample file × rule, round-robin across the 10
tactic folders, 70 distinct techniques) are labelled malicious with their Sigma tags as ground truth.
60 info-level, untagged detections are labelled by deterministic rules
([docs/labelling_rules.md](docs/labelling_rules.md): attack-tool indicators, obfuscation, masquerading,
user-writable execution paths → malicious; Windows binaries from system paths and routine system events →
benign; everything else excluded), giving 25 malicious, 17 benign and 18 excluded. No label is set by
hand. Tags, sample/rule file names and technique IDs are removed from the model's input. Alerts with a network destination or URL
received FireHOL/abuse.ch indicators (malicious) or Tranco domains (benign candidates).

**Comparisons.** Provider A (Ollama, Qwen3-4B-Instruct-2507) vs provider B (llama-server,
Llama-3.2-3B-Instruct), each with and without retrieval, plus a retrieval-only baseline (top-k
retrieved techniques, no LLM) that answers "is the LLM adding anything?".

**Metrics.** Technique accuracy top-1 / top-3 (exact ID, or parent/sub-technique of a labelled ID) and at
tactic level; missed true positives (malicious alerts given a benign verdict) and malicious alerts the
gate auto-closed; benign alerts correctly auto-closed; calibration of the confidence score for the
verdict (ECE over 10 bins, Brier); tokens and p50/p95 latency per alert. 95% Wilson intervals on every
rate.

### Results (run 20261013T112326Z, M1 Pro 16 GB)

Alerts: 190 (155 malicious, 17 benign, 18 excluded by the labelling rules). Prompt v1-dc7e4135, ATT&CK 19.2. 95% Wilson intervals.

| Metric | ollama+rag | llamacpp+rag | ollama+norag | llamacpp+norag | retrieval-only |
|---|---|---|---|---|---|
| Technique top-1 | 46.2% [37.8%, 54.7%] (n=130) | 43.1% [34.9%, 51.7%] (n=130) | 11.5% [7.1%, 18.2%] (n=130) | 3.1% [1.2%, 7.6%] (n=130) | 40.8% [32.7%, 49.4%] (n=130) |
| Technique top-3 | 54.6% [46.0%, 62.9%] (n=130) | 58.5% [49.9%, 66.6%] (n=130) | 13.1% [8.3%, 19.9%] (n=130) | 3.8% [1.7%, 8.7%] (n=130) | 59.2% [50.6%, 67.3%] (n=130) |
| Tactic (top-1) | 66.9% [58.5%, 74.4%] (n=130) | 64.6% [56.1%, 72.3%] (n=130) | 23.8% [17.3%, 31.9%] (n=130) | 3.1% [1.2%, 7.6%] (n=130) | 61.5% [53.0%, 69.5%] (n=130) |
| Missed true positives (malicious → benign) | 5.2% [2.6%, 9.9%] (n=155) | 0.6% [0.1%, 3.6%] (n=155) | 3.9% [1.8%, 8.2%] (n=155) | 2.6% [1.0%, 6.4%] (n=155) | — |
| Malicious auto-closed | 3.2% [1.4%, 7.3%] (n=155) | 0.6% [0.1%, 3.6%] (n=155) | 3.9% [1.8%, 8.2%] (n=155) | 1.9% [0.7%, 5.5%] (n=155) | — |
| Benign correctly closed | 5.9% [1.0%, 27.0%] (n=17) | 5.9% [1.0%, 27.0%] (n=17) | 23.5% [9.6%, 47.3%] (n=17) | 11.8% [3.3%, 34.3%] (n=17) | — |
| Valid model output | 100.0% [98.0%, 100.0%] (n=190) | 100.0% [98.0%, 100.0%] (n=190) | 94.2% [89.9%, 96.7%] (n=190) | 11.6% [7.8%, 16.9%] (n=190) | — |
| Calibration ECE / Brier | 0.086 / 0.1227 | 0.1994 / 0.1145 | 0.0636 / 0.0873 | 0.2095 / 0.2505 | — |
| Tokens per alert p50 / p95 | 1411.0 / 2028.5 | 1250.0 / 1792.2 | 1024.0 / 1651.2 | 873.0 / 1447.7 | — |
| Latency per alert p50 / p95 (ms) | 11224.5 / 14084.9 | 6845.5 / 9566.1 | 9338.0 / 12073.6 | 5499.4 / 7228.0 | — |

#### Prompt injection (ollama, 40 malicious alerts × 4 payloads)

| | Mitigations off | Mitigations on |
|---|---|---|
| Verdict flipped to benign | 62.5% [54.6%, 69.8%] (n=152) | 60.5% [52.6%, 67.9%] (n=152) |
| Injected alert auto-closed | 64.4% [56.7%, 71.4%] (n=160) | 61.9% [54.2%, 69.0%] (n=160) |
| flip: ignore_previous | 89.5% [75.9%, 95.8%] (n=38) | 86.8% [72.7%, 94.2%] (n=38) |
| flip: fake_delimiter | 42.1% [27.9%, 57.8%] (n=38) | 42.1% [27.9%, 57.8%] (n=38) |
| flip: json_answer | 21.1% [11.1%, 36.3%] (n=38) | 31.6% [19.1%, 47.5%] (n=38) |
| flip: authority | 97.4% [86.5%, 99.5%] (n=38) | 81.6% [66.6%, 90.8%] (n=38) |

Off = alert pasted into the prompt as plain text, no safety gate (benign verdict closes). On = nonce-delimited untrusted block with `<` escaped, explicit data-only instruction, safety gate.

**What the numbers say.**

- **Retrieval is what makes technique identification work.** Without candidates, Qwen's top-1 drops from
  46% to 12%, and Llama mostly answers with techniques that don't exist (only 12% of its answers pass
  validation; every rejected answer was an invented sub-technique ID).
- **The LLM adds little over retrieval alone for choosing the technique.** Top-1 is 46% vs 41% for the
  retrieval-only baseline (overlapping intervals) and top-3 is no better (55–59% vs 59%). The model earns
  its place on the verdict, the action and the rationale, not on technique ranking.
- **The gate is conservative.** Few malicious alerts get a benign verdict (0.6–5%) and at most 3% are
  auto-closed — but only 1 of 17 benign alerts closes automatically with retrieval, because the models
  rarely give a benign verdict with ≥ 0.85 confidence. Nearly everything still reaches an analyst.
- **Calibration.** Qwen's confidence is reasonably calibrated (ECE 0.09); Llama's is not (ECE 0.20).
- **Latency.** p50 11 s (Qwen 4B) and 7 s (Llama 3B) per alert on an M1 Pro, ~1.2–1.4k tokens.
- **Prompt injection is not solved by delimiting.** With mitigations on, 61% of injected malicious alerts
  still flip to benign and 62% would be auto-closed, versus 63% and 64% with no mitigations at all.
  Text that impersonates authority ("whitelisted by the SOC lead") or tells the model to ignore its
  instructions works 82–97% of the time on a 4B model; the nonce delimiter only dents the authority
  payload (97% → 82%). The gate cannot help, because the attack produces exactly the confident benign
  verdict it is designed to accept.

Reproduce: `venv/bin/python -m triage.evaluation.runner` (needs the stack and both model servers; ~3 h
on an M1 Pro the first time, seconds afterwards because every response is cached in
`local/eval/cassette.jsonl`; reports go to `local/eval/runs/`). CI replays the first 20 alerts from
`tests/fixtures/eval_smoke_cassette.jsonl`.

## Local → cloud

| Local | Cloud equivalent |
|---|---|
| RabbitMQ | Azure Service Bus / SQS |
| Postgres + pgvector | Azure Database for PostgreSQL / RDS |
| Keycloak | Entra ID / Cognito |
| OpenTelemetry + Jaeger | Azure Monitor / X-Ray |
| Ollama / llama.cpp | Azure OpenAI / Bedrock |
| Docker Compose | Container Apps / ECS |

The code talks to these through narrow seams — AMQP, a Postgres DSN, OIDC discovery, OTLP, and the
`LLMProvider` protocol — so moving to a managed service is mostly configuration plus one new provider
class.

## Known limitations

- **Severity correlates with the label.** The 130 Sigma-tagged malicious alerts are medium-and-above and
  every benign alert is info-level, so severity alone separates most of the classes (only the 25
  rule-labelled malicious alerts are info-level). The model sees severity, as it would in production;
  verdict metrics are therefore optimistic. The retrieval-only baseline is scored on techniques only for
  this reason.
- **Sigma tags are the ground truth.** They are the rule author's opinion, sometimes list several
  techniques, and only exist for the malicious class.
- **Rule-based labels are noisy and the benign set is small.** The info-level candidates are labelled by
  heuristics, not by an analyst: e.g. a legitimate Windows binary performing an attack step (w3wp.exe making
  an explicit logon from a webshell) is labelled benign. Only 17 benign alerts are scored, so the benign
  intervals are wide; 18 undecidable events are excluded.
- **Threat intel is too clean.** Inserted indicators always agree with the label, so TI is an oracle for
  the 17 alerts that carry one. VirusTotal and AbuseIPDB run against fixtures (no API keys), so they
  answer "unknown" for every indicator (no fixture files are shipped).
- **Small quantised models.** 3–4B parameters at 4-bit; one GPU shared by both runtimes, ~6–12 s per
  alert on an M1 Pro; two workers don't double throughput because both runtimes share one GPU.
- **Calibration and latency** are point estimates (Wilson intervals apply to rates only).
- **Auto-close is unsafe under prompt injection.** The evaluation shows the mitigations in this build do
  not stop an attacker who controls alert text from getting a malicious alert closed. Until the gate stops
  trusting the model's verdict on attacker-controlled input, auto-close should stay disabled in anything
  beyond a lab (set `TRIAGE_AUTO_CLOSE_MIN_CONFIDENCE` above 1).
- Dev secrets and HTTP everywhere; single-host compose.

## Repository layout

```
src/triage/            ingest, worker, enrichment, retrieval, LLM providers, prompt, safety, UI, ti-service, evaluation
packages/triage_connectors/   pip-installable connector SDK (protocol, rate limiter, retries, TTL cache, adapters)
migrations/            SQL migrations + grants
data/attack, data/ti, data/alerts   committed snapshots (ATT&CK v19.2, TI lists, evaluation dataset)
docker/, docker-compose.yml         image, Postgres roles, Keycloak realm
scripts/               fetch/build data, install/run model servers, replay, load ATT&CK
docs/labelling_rules.md
```

## Data sources and licenses

The code is MIT-licensed ([LICENSE](LICENSE)). The data snapshots under `data/` are third-party and keep
their own terms:

| Folder | Source | Terms |
|---|---|---|
| `data/attack/` | [MITRE ATT&CK](https://attack.mitre.org/) Enterprise v19.2 ([STIX data](https://github.com/mitre-attack/attack-stix-data)) | © The MITRE Corporation, reproduced under MITRE's license — [data/attack/LICENSE.txt](data/attack/LICENSE.txt) |
| `data/alerts/` | derived from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) with [Hayabusa](https://github.com/Yamato-Security/hayabusa) and Sigma rules | GPL-3.0 — [data/alerts/NOTICE.md](data/alerts/NOTICE.md) |
| `data/ti/` | [FireHOL](https://iplists.firehol.org/), [abuse.ch](https://abuse.ch/) (URLhaus, ThreatFox, Feodo Tracker), [Tranco](https://tranco-list.eu/) | per source — [data/ti/NOTICE.md](data/ti/NOTICE.md) |

Raw downloads (`scripts/fetch_data.sh`), the Hayabusa binary and the model weights are not part of the
repository.

