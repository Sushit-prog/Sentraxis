"""Replay injector: streams a labeled scenario file into events:raw.

- JSONL scenario format, one CanonicalEvent per line.
- Messages are validated then pipelined in XADD_BATCH chunks (one round trip
  per chunk); an invalid line aborts the run and discards its pending chunk,
  so a broken scenario never partially executes.
- Checkpointed in Redis (`replay:checkpoint:<name>` = next line index sent),
  advanced only after each chunk is confirmed, so interrupted replays resume
  exactly where they stopped. Re-running a completed replay against an
  already-populated DB is safe: duplicates are absorbed downstream by the
  unique constraint on event_id.
"""

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

import redis
import structlog

from app.domain.events import CanonicalEvent
from app.workers.streams import RAW_STREAM, XADD_BATCH

logger = structlog.get_logger(__name__)


def checkpoint_key(scenario_name: str) -> str:
    return f"replay:checkpoint:{scenario_name}"


@dataclass(slots=True)
class InjectionSummary:
    scenario: str
    total_lines: int
    sent: int
    skipped_by_checkpoint: int
    completed: bool


class ReplayInjector:
    def __init__(
        self,
        redis_client: redis.Redis,
        scenario_path: Path,
        eps: int = 0,
    ) -> None:
        self.redis = redis_client
        self.scenario_path = scenario_path
        self.eps = eps  # 0 = maximum speed
        self.name = scenario_path.stem
        self._key = checkpoint_key(self.name)

    def _load_lines(self) -> list[str]:
        # Stream line-by-line: avoids the 2-3x transient allocation of
        # read_text()+splitlines() on large scenario files.
        lines: list[str] = []
        with self.scenario_path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line:
                    lines.append(line)
        if not lines:
            raise ValueError(f"scenario file is empty: {self.scenario_path}")
        return lines

    def _parse_line(self, line: str, seq: int) -> bytes:
        try:
            event = CanonicalEvent.model_validate(json.loads(line))
            return event.model_dump_json().encode("utf-8")
        except Exception as exc:  # fail fast: bad scenarios must not run half-way
            raise ValueError(f"scenario '{self.name}' line {seq + 1} invalid: {exc}") from exc

    def _pace(self, sent: int, started_at: float) -> None:
        expected_elapsed = sent / self.eps
        actual_elapsed = time.monotonic() - started_at
        if actual_elapsed < expected_elapsed:
            time.sleep(expected_elapsed - actual_elapsed)

    def reset(self) -> None:
        self.redis.delete(self._key)
        logger.info("replay_checkpoint_reset", scenario=self.name)

    def run(self, reset: bool = False, limit: int | None = None) -> InjectionSummary:
        lines = self._load_lines()
        if reset:
            self.reset()

        start = min(self.checkpoint(), len(lines))
        logger.info(
            "replay_started",
            scenario=self.name,
            lines=len(lines),
            resume_from=start,
            eps=self.eps or "max",
        )

        sent = 0
        started_at = time.monotonic()
        buffer: list[dict[str, str]] = []

        def flush() -> None:
            """Send buffered messages in one round trip, then checkpoint.

            Checkpoint is advanced only AFTER the batch is confirmed sent, so a
            crash between XADD and SET replays (idempotently) rather than skips.
            """
            nonlocal sent
            if not buffer:
                return
            pipe = self.redis.pipeline(transaction=False)
            for fields in buffer:
                pipe.xadd(RAW_STREAM, cast("Any", fields))
            pipe.execute()
            self.redis.set(self._key, start + sent)
            buffer.clear()

        for seq in range(start, len(lines)):
            if limit is not None and sent >= limit:
                break
            payload = self._parse_line(lines[seq], seq)
            buffer.append({"payload": payload.decode("utf-8"), "seq": str(seq)})
            sent += 1
            if len(buffer) >= XADD_BATCH:
                flush()
            if self.eps > 0 and sent % XADD_BATCH == 0:
                # pacing per batch keeps max-speed mode truly fast while still
                # honoring rate limits at lower eps
                self._pace(sent, started_at)
        flush()

        next_index = start + sent
        if next_index >= len(lines) and limit is None:
            self.redis.set(self._key, next_index)

        summary = InjectionSummary(
            scenario=self.name,
            total_lines=len(lines),
            sent=sent,
            skipped_by_checkpoint=start,
            completed=(next_index >= len(lines) and limit is None),
        )
        logger.info("replay_finished", **asdict(summary))
        return summary

    def checkpoint(self) -> int:
        value = cast("str | None", self.redis.get(self._key))
        return int(value) if value else 0


def main() -> None:  # pragma: no cover - CLI entrypoint
    parser = argparse.ArgumentParser(description="Replay a labeled scenario into events:raw")
    parser.add_argument("--scenario", required=True, type=Path, help="Path to .jsonl scenario file")
    parser.add_argument("--eps", type=int, default=None, help="Events per second (0 = max speed)")
    parser.add_argument(
        "--reset", action="store_true", help="Discard checkpoint, restart from line 0"
    )
    args = parser.parse_args()

    from app.config import get_settings
    from app.workers.connections import create_redis

    settings = get_settings()
    injector = ReplayInjector(
        redis_client=create_redis(settings),
        scenario_path=args.scenario,
        eps=settings.replay_default_eps if args.eps is None else args.eps,
    )
    try:
        injector.run(reset=args.reset)
    except KeyboardInterrupt:
        logger.warning("replay_interrupted_checkpoint_saved", scenario=injector.name)


if __name__ == "__main__":
    main()
