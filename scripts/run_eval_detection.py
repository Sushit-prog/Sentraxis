"""Offline detection evaluation: replay labeled scenarios end-to-end, score.

Pipeline under test: injector -> Redis -> normalizer -> PostgreSQL -> detector
worker (running as a service). The script resets detection state, replays,
waits for the worker cursor to pass the last event, then scores detections
against ground-truth labels with bucket-window coverage expansion.

Usage (full stack up):
    uv run python scripts/run_eval_detection.py \
        --scenario scenarios/port_scan_probe.jsonl [--name eval_run]

Coverage model: one detection covers all attack-labeled events of the SAME
source entity inside its bucket window [bucket_start, bucket_start + window).
This reflects how an analyst reads a sweep alert: it explains the burst, not
just the single triggering packet.
"""

import argparse
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from app.config import get_settings
from app.persistence.db import create_db_engine
from app.workers.connections import create_redis
from app.workers.injector import ReplayInjector

logger = structlog.get_logger(__name__)

DETECTOR_CURSOR = "detector"
TIMEOUT_S = 300.0


def reset_state(engine: Engine, attempts: int = 3) -> None:
    """Clear derived state so every eval run is independent and deterministic.

    TRUNCATE takes ACCESS EXCLUSIVE and queues behind any open reader; bounded
    lock/statement timeouts plus retry prevent a straggler connection from
    hanging this script (or the whole pipeline) indefinitely.
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout = '5s'"))
                conn.execute(text("SET LOCAL statement_timeout = '30s'"))
                # Full slate: reprocessing historical events after a cursor
                # reset would poison tumbling buckets with out-of-order data.
                conn.execute(
                    text(
                        "TRUNCATE detections, entity_metric_state, worker_cursors,"
                        " events, entities RESTART IDENTITY CASCADE"
                    )
                )
            logger.info("detection_state_reset")
            return
        except OperationalError as exc:  # timeout / lock wait
            last_error = exc
            logger.warning("reset_state_blocked_retrying", attempt=attempt)
            time.sleep(2.0 * attempt)
    raise SystemExit(f"reset_state failed after {attempts} attempts: {last_error}")


def _max_event_id(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text("SELECT coalesce(max(id), 0) FROM events")).scalar_one())


def _cursor_value(engine: Engine) -> int:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT last_event_id FROM worker_cursors WHERE name = :n"), {"n": DETECTOR_CURSOR}
        ).first()
        return int(row[0]) if row else 0


def _load_detections(engine: Engine) -> list[dict[str, Any]]:
    import json as _json

    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT d.detector, d.score, d.severity, d.details, "
                    "e.ts, e.src_entity_id, e.ground_truth_label "
                    "FROM detections d JOIN events e ON e.id = d.event_id"
                )
            )
            .mappings()
            .all()
        )
    out = []
    for r in rows:
        details = r["details"]
        if isinstance(details, str):
            details = _json.loads(details)
        ts = r["ts"] if r["ts"].tzinfo else r["ts"].replace(tzinfo=UTC)
        out.append({**dict(r), "details": details, "ts": ts})
    return out


def score(scenario_path: Path, engine: Engine) -> dict[str, Any]:
    """Replay one scenario and compute event-coverage metrics."""
    settings = get_settings()
    redis_client = create_redis(settings)

    reset_state(engine)

    events = [
        json.loads(line)
        for line in scenario_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    injector = ReplayInjector(redis_client, scenario_path, eps=0)
    injector.run(reset=True)

    # Stable-state wait: done only when the detector cursor has caught up with
    # max(event.id) AND both values stopped moving between two samples. Robust
    # to replay dedupe (no new rows) and ingestion lag.
    deadline = time.monotonic() + TIMEOUT_S
    prev: tuple[int, int] | None = None
    while time.monotonic() < deadline:
        snapshot = (_max_event_id(engine), _cursor_value(engine))
        if snapshot == prev and snapshot[1] >= snapshot[0]:
            break
        prev = snapshot
        time.sleep(1.0)
    else:
        raise SystemExit(f"timeout waiting for pipeline quiescence (last={prev})")

    window_s = settings.det_window_seconds
    detections = _load_detections(engine)

    # entity id -> identifier for joining detections back to scenario entries
    with engine.connect() as conn:
        ent_rows = conn.execute(text("SELECT id, identifier FROM entities")).all()
    id_to_ident = {int(r[0]): r[1] for r in ent_rows}

    # Coverage expansion: a detection covers same-source events inside its bucket window.
    covered_attack: set[int] = set()
    covered_benign: set[int] = set()
    for det in detections:
        bstart_raw = det["details"].get("bucket_start")
        if not bstart_raw:
            continue
        start = datetime.fromisoformat(bstart_raw)
        end = start + timedelta(seconds=window_s)
        src_ident = id_to_ident.get(det["src_entity_id"])
        if src_ident is None:
            continue
        for i, ev in enumerate(events):
            if ev["src_entity"]["identifier"] != src_ident:
                continue
            ev_ts = datetime.fromisoformat(ev["ts"].replace("Z", "+00:00"))
            if start <= ev_ts < end:
                if ev.get("ground_truth_label") is True:
                    covered_attack.add(i)
                elif ev.get("ground_truth_label") is False:
                    covered_benign.add(i)

    attacks_total = sum(1 for e in events if e.get("ground_truth_label") is True)
    benign_total = sum(1 for e in events if e.get("ground_truth_label") is False)

    tp = len(covered_attack)
    fp = len(covered_benign)
    fn = attacks_total - tp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / attacks_total if attacks_total else 0.0
    fpr = fp / benign_total if benign_total else 0.0

    per_detector: dict[str, int] = {}
    for det in detections:
        per_detector[det["detector"]] = per_detector.get(det["detector"], 0) + 1

    return {
        "scenario": scenario_path.name,
        "events": len(events),
        "attacks": attacks_total,
        "benign": benign_total,
        "detections_emitted": len(detections),
        "per_detector": per_detector,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fpr": round(fpr, 4),
    }


def write_report(results: list[dict], path: Path) -> None:
    lines = [
        "# Detection evaluation report",
        "",
        f"_Generated {datetime.now(UTC).isoformat()} by scripts/run_eval_detection.py_",
        "",
        (
            "| Scenario | Events | Attacks | Benign | Detections"
            " | TP | FP | FN | Precision | Recall | FPR |"
        ),
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in results:
        lines.append(
            f"| {r['scenario']} | {r['events']} | {r['attacks']} | {r['benign']} "
            f"| {r['detections_emitted']} | {r['tp']} | {r['fp']} | {r['fn']} "
            f"| {r['precision']} | {r['recall']} | {r['fpr']} |"
        )
    lines += ["", "## Per-detector emission counts", ""]
    for r in results:
        lines.append(f"- **{r['scenario']}**: {json.dumps(r['per_detector'])}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"report written -> {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run offline detection evaluation")
    parser.add_argument("--scenario", type=Path, action="append", required=True)
    parser.add_argument("--report", type=Path, default=Path("docs/evaluation/detection-report.md"))
    args = parser.parse_args()

    engine = create_db_engine(get_settings())
    results = []
    for scenario in args.scenario:
        result = score(scenario, engine)
        results.append(result)
        print(json.dumps(result, indent=2))
    write_report(results, args.report)


if __name__ == "__main__":
    main()
