"""Integration tests: replay injector checkpoint/resume semantics."""

import json

import pytest

from app.workers.injector import ReplayInjector
from app.workers.streams import RAW_STREAM
from tests.integration._factories import make_event_dict
from tests.integration.test_normalizer import db_event_count, make_normalizer  # noqa: F401

pytestmark = [pytest.mark.integration]


def _scenario(tmp_path, count: int):
    path = tmp_path / "mini_scenario.jsonl"
    path.write_text(
        "\n".join(json.dumps(make_event_dict(i)) for i in range(count)), encoding="utf-8"
    )
    return path


def test_checkpoint_resume_completes_replay(rclient, tmp_path) -> None:
    injector = ReplayInjector(rclient, _scenario(tmp_path, 5), eps=0)

    partial = injector.run(limit=3)
    assert partial.sent == 3
    assert partial.completed is False
    assert injector.checkpoint() == 3
    assert rclient.xlen(RAW_STREAM) == 3

    resumed = injector.run()
    assert resumed.sent == 2
    assert resumed.completed is True
    assert injector.checkpoint() == 5
    assert rclient.xlen(RAW_STREAM) == 5


def test_reset_discards_checkpoint(rclient, tmp_path) -> None:
    injector = ReplayInjector(rclient, _scenario(tmp_path, 4), eps=0)
    injector.run(limit=2)
    assert injector.checkpoint() == 2

    injector.run(reset=True)
    assert injector.checkpoint() == 4  # full re-run from line 0
    assert rclient.xlen(RAW_STREAM) == 6  # 2 + 4 (dupes allowed at stream level)


def test_invalid_line_fails_fast_before_sending_rest(rclient, tmp_path) -> None:
    path = tmp_path / "bad_scenario.jsonl"
    lines = [json.dumps(make_event_dict(1)), "{broken json", json.dumps(make_event_dict(3))]
    path.write_text("\n".join(lines), encoding="utf-8")

    injector = ReplayInjector(rclient, path, eps=0)
    with pytest.raises(ValueError, match="line 2"):
        injector.run()

    # Batching contract: the failed line aborts its entire pending chunk, so
    # nothing half-parsed or partially-validated reaches the stream.
    assert rclient.xlen(RAW_STREAM) == 0


def test_injected_events_flow_through_normalizer_exactly_once(
    rclient, session_factory, clean_db, tmp_path
) -> None:
    injector = ReplayInjector(rclient, _scenario(tmp_path, 5), eps=0)
    injector.run()

    norm = make_normalizer(rclient, session_factory)
    first = norm.process_batch()
    assert first.inserted == 5 and first.duplicates == 0
    assert db_event_count(session_factory) == 5

    # full scenario replay again: storage stays exactly-once
    injector.run(reset=True)
    second = norm.process_batch()
    assert second.inserted == 0 and second.duplicates == 5
    assert db_event_count(session_factory) == 5
