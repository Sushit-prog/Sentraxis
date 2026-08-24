# Detection evaluation report

_Generated 2026-08-24T13:57:04.395556+00:00 by scripts/run_eval_detection.py_

| Scenario | Events | Attacks | Benign | Detections | TP | FP | FN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| port_scan_probe.jsonl | 30 | 21 | 9 | 1 | 21 | 0 | 0 | 1.0 | 1.0 | 0.0 |
| bulk_bench.jsonl | 50000 | 5000 | 45000 | 4 | 5000 | 0 | 0 | 1.0 | 1.0 | 0.0 |

## Per-detector emission counts

- **port_scan_probe.jsonl**: {"port_velocity": 1}
- **bulk_bench.jsonl**: {"port_velocity": 4}

