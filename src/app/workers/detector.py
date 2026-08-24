"""Detection worker: consumes events incrementally by DB cursor (ADR-005).

Loop: fetch events with id > cursor (ordered) → run each detector over the
batch → in ONE transaction: insert detections (conflict-nothing) + advance
cursor. Crash between detectors and commit reprocesses the same batch; the
unique constraint on (event_id, detector, version) absorbs duplicates.
"""

import time

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.detectors import DETECTOR_CURSOR_NAME, EventView, build_registry
from app.persistence.models import DetectionRow, EventRow, WorkerCursorRow
from app.persistence.repository import InsertReport

logger = structlog.get_logger(__name__)


def get_cursor(session: Session, name: str = DETECTOR_CURSOR_NAME) -> int:
    row = session.get(WorkerCursorRow, name)
    return int(row.last_event_id) if row else 0


def set_cursor(session: Session, value: int, name: str = DETECTOR_CURSOR_NAME) -> None:
    row = session.get(WorkerCursorRow, name)
    if row is None:
        row = WorkerCursorRow(name=name, last_event_id=value)
        session.add(row)
    else:
        from sqlalchemy import func as sa_func

        row.last_event_id = value
        row.updated_at = sa_func.now()


def record_detections(session: Session, detections: list) -> InsertReport:
    """Insert detections idempotently; returns inserted/duplicates."""
    if not detections:
        return InsertReport(inserted=0, duplicates=0)
    values = [
        {
            "event_id": d.event_id,
            "entity_id": d.entity_id,
            "detector": d.detector,
            "detector_version": d.detector_version,
            "score": d.score,
            "severity": d.severity,
            "details": d.details,
        }
        for d in detections
    ]
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    stmt = (
        pg_insert(DetectionRow)
        .values(values)
        .on_conflict_do_nothing(index_elements=["event_id", "detector", "detector_version"])
        .returning(DetectionRow.id)
    )
    ids = session.execute(stmt).scalars().all()
    return InsertReport(inserted=len(ids), duplicates=len(detections) - len(ids))


class DetectionWorker:
    def __init__(
        self,
        session_factory: sessionmaker,
        detectors: list,
        batch_size: int,
    ) -> None:
        self.session_factory = session_factory
        self.detectors = detectors
        self.batch_size = batch_size

    def _fetch_batch(self, session: Session, cursor: int) -> list[EventView]:
        rows = session.execute(
            select(
                EventRow.id,
                EventRow.ts,
                EventRow.src_entity_id,
                EventRow.dst_entity_id,
                EventRow.features["dst_port"].as_integer(),
            )
            .where(EventRow.id > cursor)
            .order_by(EventRow.id)
            .limit(self.batch_size)
        ).all()
        return [
            EventView(
                id=r.id,
                ts=r.ts,
                src_entity_id=r.src_entity_id,
                dst_entity_id=r.dst_entity_id,
                dst_port=int(r[4] or 0),
                label=None,
            )
            for r in rows
        ]

    def tick(self) -> dict:
        """Process one batch. Returns summary; empty result means idle."""
        with self.session_factory() as session:
            cursor = get_cursor(session)
            views = self._fetch_batch(session, cursor)
            if not views:
                return {"processed": 0}

            detections: list = []
            for detector in self.detectors:
                try:
                    detections.extend(detector.process(session, views))
                except Exception:  # noqa: BLE001 - one bad detector must not stall the stream
                    logger.exception(
                        "detector_failed", detector=getattr(detector, "describe", lambda: {})()
                    )

            report = record_detections(session, detections)
            max_id = max(v.id for v in views)
            set_cursor(session, max_id)
            session.commit()

            summary = {
                "processed": len(views),
                "through_id": max_id,
                "detections_inserted": report.inserted,
                "duplicates": report.duplicates,
                "detections_emitted": len(detections),
            }
            logger.info("detection_batch", **summary)
            return summary


def main() -> None:  # pragma: no cover - process entrypoint
    from app.config import get_settings
    from app.persistence.db import create_db_engine, create_session_factory

    settings = get_settings()
    session_factory = create_session_factory(create_db_engine(settings))
    registry = build_registry(settings)
    logger.info("detector_worker_started", detectors=[d.describe() for d in registry])

    worker = DetectionWorker(session_factory, registry, settings.det_batch_size)
    while True:
        result = worker.tick()
        if result.get("processed", 0) == 0:
            time.sleep(settings.det_poll_interval_s)


if __name__ == "__main__":
    main()
