"""Measure end-to-end ingestion throughput: injector -> Redis -> normalizer -> PostgreSQL.

Non-destructive: records the current event-table count as a baseline, injects
the scenario, waits for the delta to land, reports wall-clock rate. Run with
the full stack up:

    docker compose up -d --build
    uv run python scripts/bench_replay.py --scenario scenarios/bulk_bench.jsonl
"""

import argparse
import json
import time
from pathlib import Path

import structlog
from sqlalchemy import Engine, text

from app.config import get_settings
from app.persistence.db import create_db_engine
from app.workers.connections import create_redis
from app.workers.injector import ReplayInjector

logger = structlog.get_logger(__name__)

POLL_INTERVAL_S = 0.25
TIMEOUT_S = 600.0


def _event_count(engine: Engine) -> int:
    with engine.connect() as conn:
        return conn.execute(text("SELECT count(*) FROM events")).scalar_one()


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark replay ingestion throughput")
    parser.add_argument("--scenario", required=True, type=Path)
    args = parser.parse_args()

    settings = get_settings()
    redis_client = create_redis(settings)
    engine = create_db_engine(settings)

    baseline = _event_count(engine)
    logger.info("bench_started", scenario=str(args.scenario), baseline_events=baseline)

    injector = ReplayInjector(redis_client, args.scenario, eps=0)

    t0 = time.monotonic()
    summary = injector.run(reset=True)
    sent = summary.sent
    if sent == 0:
        logger.error("bench_aborted_no_events")
        raise SystemExit(1)

    expected_total = baseline + sent
    ingested = _event_count(engine)
    while ingested < expected_total and time.monotonic() - t0 < TIMEOUT_S:
        time.sleep(POLL_INTERVAL_S)
        ingested = _event_count(engine)
    elapsed = time.monotonic() - t0

    complete = ingested >= expected_total
    result = {
        "scenario": args.scenario.name,
        "events_sent": sent,
        "events_ingested": ingested - baseline,
        "elapsed_seconds": round(elapsed, 2),
        "ingest_events_per_sec": round((ingested - baseline) / elapsed, 1) if elapsed else 0.0,
        "complete": complete,
    }
    logger.info("throughput_result", **result)
    print(json.dumps(result, indent=2))
    if not complete:
        raise SystemExit(f"timeout: only {ingested - baseline}/{sent} events landed")


if __name__ == "__main__":
    main()
