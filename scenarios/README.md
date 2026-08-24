# Attack scenarios

Labeled replay inputs for the ingestion pipeline and evaluation harness.

## Format

JSONL — one `CanonicalEvent` per line (strict schema; see
`src/app/domain/events.py`). Every event carries:

| Field                | Meaning                                              |
| -------------------- | ---------------------------------------------------- |
| `event_id`           | Stable UUID — idempotency key across replays         |
| `ts`                 | Event occurrence time (UTC)                          |
| `src_entity`/`dst_entity` | `{type, identifier}` host refs (IP or hostname) |
| `ground_truth_label` | `true` = attack evidence, `false` = benign, `null` = unknown |
| `features`           | Typed flow projection (ports, bytes, pkts, state...) |

## Replaying

```bash
uv run python -m app.workers.injector --scenario scenarios/port_scan_probe.jsonl --eps 200
uv run python -m app.workers.injector --scenario scenarios/port_scan_probe.jsonl --reset   # from line 0
```

The injector checkpoints progress in Redis (`replay:checkpoint:<name>`), so an
interrupted run resumes where it stopped. Duplicate replays are absorbed by the
database's unique constraint on `event_id`.

## Scenarios

| File                  | Story                                                        |
| --------------------- | ------------------------------------------------------------ |
| `port_scan_probe.jsonl` | Benign web traffic to a server, followed by a rapid TCP SYN sweep across 21 service ports from an external host (`203.0.113.77`), then normal traffic resumes. Ground truth: events 7–27 are malicious. |
| `bulk_bench.jsonl`      | 50k synthetic flows (seeded): benign web/DNS mix + interleaved SYN-sweep bursts from two external attackers. Used by `make bench`; regenerate with any seed — event ids are seed-scoped so re-benchmarks never collide. |

## Preparing real data

CICIDS2017 (*GeneratedLabelledFlows* variant only — it carries IPs/Timestamps):

```bash
uv run python scripts/prepare_cicids.py \
  --input "CSVs/Friday-WorkingHours-Afternoon/*.csv" \
  --name cicids_friday --max-events 50000
```

Attacks are sampled preferentially (≤60% of budget) so evidence isn't drowned
by the benign majority; provenance and label statistics land in
`<name>.meta.json`. The MachineLearningCVE variant is rejected explicitly (no
entity identity).
