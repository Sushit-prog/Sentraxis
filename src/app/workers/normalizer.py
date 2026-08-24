"""Normalizer worker: events:raw -> validated CanonicalEvents -> PostgreSQL -> ACK.

Delivery semantics:
- At-least-once from the stream; the uq_events_event_id unique constraint makes
  the storage effect exactly-once.
- Malformed payloads are deterministic poison: dead-lettered immediately (no
  pointless retries), original message ACKed, reason logged.
- Transient DB failures leave messages un-ACKed for redelivery/reclaim.
"""

import os
import socket
import time
from dataclasses import dataclass, field
from typing import cast

import redis
import structlog
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.domain.events import CanonicalEvent, parse_event_payload
from app.persistence.repository import NonRetryableBatchError, persist_batch
from app.workers.streams import (
    CLAIM_IDLE_MS,
    DEAD_STREAM,
    NORMALIZER_GROUP,
    RAW_STREAM,
    READ_BLOCK_MS,
)

logger = structlog.get_logger(__name__)

INLINE_RETRY_ATTEMPTS = 3
INLINE_RETRY_BACKOFF_S = 0.25


@dataclass(slots=True)
class BatchResult:
    received: int = 0
    parsed_ok: int = 0
    dead_lettered: int = 0
    inserted: int = 0
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)


class Normalizer:
    def __init__(
        self,
        redis_client: redis.Redis,
        session_factory: sessionmaker,
        batch_size: int,
        consumer_name: str | None = None,
        claim_idle_ms: int = CLAIM_IDLE_MS,
        read_block_ms: int = READ_BLOCK_MS,
    ) -> None:
        self.redis = redis_client
        self.session_factory = session_factory
        self.batch_size = batch_size
        self.claim_idle_ms = claim_idle_ms
        self.read_block_ms = read_block_ms
        self.consumer = consumer_name or f"{socket.gethostname()}-{os.getpid()}"
        self._group_ready = False

    def ensure_group(self) -> None:
        try:
            self.redis.xgroup_create(RAW_STREAM, NORMALIZER_GROUP, id="0", mkstream=True)
            logger.info("stream_group_created", stream=RAW_STREAM, group=NORMALIZER_GROUP)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._group_ready = True

    def process_batch(self) -> BatchResult:
        """Claim stale work, read new work, persist atomically, ACK per outcome."""
        if not self._group_ready:
            self.ensure_group()

        entries = self._collect_entries()
        result = BatchResult(received=len(entries))
        if not entries:
            return result

        valid_events: list[tuple[bytes, CanonicalEvent]] = []
        for msg_id, fields in entries:
            payload = fields.get("payload")
            try:
                if not isinstance(payload, (str, bytes)):
                    raise ValueError("message missing 'payload' field")
                valid_events.append((msg_id, parse_event_payload(payload)))
                result.parsed_ok += 1
            except ValueError as exc:
                self._dead_letter(msg_id, payload, str(exc))
                result.dead_lettered += 1

        if valid_events:
            self._persist_and_ack(valid_events, result)
        else:
            # only poison in this batch: all already ACKed inside _dead_letter
            pass

        logger.info(
            "batch_processed",
            received=result.received,
            inserted=result.inserted,
            duplicates=result.duplicates,
            dead_lettered=result.dead_lettered,
            errors=len(result.errors),
        )
        return result

    def _collect_entries(self) -> list[tuple[bytes, dict]]:
        entries: list[tuple[bytes, dict]] = []

        # redis-py stubs type responses as `Awaitable | T`; the sync client always
        # returns the concrete value. Casts document that contract.
        claimed_response = cast(
            "tuple[str, list[tuple[bytes, dict]], list[bytes]]",
            self.redis.xautoclaim(
                RAW_STREAM,
                NORMALIZER_GROUP,
                self.consumer,
                min_idle_time=self.claim_idle_ms,
                start_id="0-0",
                count=self.batch_size,
            ),
        )
        entries.extend(claimed_response[1])

        if len(entries) < self.batch_size:
            fresh = cast(
                "list[tuple[bytes, list[tuple[bytes, dict]]]]",
                self.redis.xreadgroup(
                    NORMALIZER_GROUP,
                    self.consumer,
                    {RAW_STREAM: ">"},
                    count=self.batch_size - len(entries),
                    block=self.read_block_ms,
                ),
            )
            for _stream, stream_entries in fresh:
                entries.extend(stream_entries)

        return entries

    def _persist_and_ack(
        self, valid_events: list[tuple[bytes, CanonicalEvent]], result: BatchResult
    ) -> None:
        events = [event for _msg_id, event in valid_events]
        msg_ids = [mid for mid, _ in valid_events]
        attempt = 0
        while True:
            try:
                with self.session_factory() as session:
                    report = persist_batch(session, events)
                result.inserted += report.inserted
                result.duplicates += report.duplicates
                self.redis.xack(RAW_STREAM, NORMALIZER_GROUP, *msg_ids)
                return
            except OperationalError as exc:
                # transient: retry inline first (healthy worker), then defer to
                # the slow reclaim path so a real outage never busy-loops.
                attempt += 1
                if attempt >= INLINE_RETRY_ATTEMPTS:
                    result.errors.append(f"transient_db_error_after_{attempt}_attempts: {exc}")
                    logger.warning(
                        "batch_deferred_to_reclaim",
                        attempts=attempt,
                        messages=len(msg_ids),
                        error=str(exc),
                    )
                    return  # leave un-ACKed; XAUTOCLAIM recovers later
                time.sleep(INLINE_RETRY_BACKOFF_S * (2 ** (attempt - 1)))
            except NonRetryableBatchError as exc:
                # isolate per event so one bad row cannot loop the whole pipeline
                result.errors.append(str(exc))
                logger.error("batch_nonretryable_falling_back_per_event", error=str(exc))
                self._persist_per_event(valid_events, result)
                return

    def _persist_per_event(
        self, valid_events: list[tuple[bytes, CanonicalEvent]], result: BatchResult
    ) -> None:
        for msg_id, event in valid_events:
            try:
                with self.session_factory() as session:
                    report = persist_batch(session, [event])
                result.inserted += report.inserted
                result.duplicates += report.duplicates
                self.redis.xack(RAW_STREAM, NORMALIZER_GROUP, msg_id)
            except Exception as exc:  # noqa: BLE001 - isolate poison row to DLQ
                result.errors.append(f"event {event.event_id}: {exc}")
                self._dead_letter(msg_id, event.model_dump_json(), f"persist_failure: {exc}")

    def _dead_letter(self, msg_id: bytes, payload: object, reason: str) -> None:
        payload_str = (
            payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(payload or "")
        )
        pipe = self.redis.pipeline(transaction=False)
        pipe.xadd(
            DEAD_STREAM, {"payload": payload_str[:16_384], "reason": reason, "origin": str(msg_id)}
        )
        pipe.xack(RAW_STREAM, NORMALIZER_GROUP, msg_id)
        pipe.execute()
        logger.warning("message_dead_lettered", origin=str(msg_id), reason=reason)

    def run_forever(self, idle_sleep_s: float = 1.0) -> None:  # pragma: no cover - entrypoint loop
        logger.info("normalizer_started", consumer=self.consumer, batch_size=self.batch_size)
        while True:
            processed = self.process_batch()
            if processed.received == 0 and processed.errors == []:
                time.sleep(idle_sleep_s)


def main() -> None:  # pragma: no cover - process entrypoint
    from app.config import get_settings
    from app.persistence.db import create_db_engine, create_session_factory
    from app.workers.connections import create_redis

    settings = get_settings()
    normalizer = Normalizer(
        redis_client=create_redis(settings),
        session_factory=create_session_factory(create_db_engine(settings)),
        batch_size=settings.event_batch_size,
    )
    try:
        normalizer.run_forever()
    except KeyboardInterrupt:
        logger.info("normalizer_stopped")


if __name__ == "__main__":
    main()
