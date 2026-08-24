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

Future scenarios (M2+): credential-stuffing auth burst, beaconing callback,
multi-stage kill-chain composite used for correlation golden-set evaluation.
