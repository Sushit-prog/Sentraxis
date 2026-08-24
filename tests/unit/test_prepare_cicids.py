"""Tests for scripts/prepare_cicids.py using a synthetic CICIDS-schema fixture.

The fixture mimics the GeneratedLabelledFlows variant: space-padded headers,
DD/MM/YYYY timestamps, BENIGN/attack labels, numeric flow features.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from app.domain.events import CanonicalEvent, parse_event_payload

spec = importlib.util.spec_from_file_location(
    "prepare_cicids", Path(__file__).parents[2] / "scripts" / "prepare_cicids.py"
)
prep = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
assert spec.loader is not None
spec.loader.exec_module(prep)

HEADER = (
    " Flow ID, Source IP, Src Port, Destination IP, Destination Port, Protocol,"
    " Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets,"
    " Total Length of Fwd Packets, Total Length of Bwd Packets, Label\n"
)


def _row(
    src: str,
    dst: str,
    ts: str,
    label: str,
    dst_port: int = 80,
    duration_us: int = 250_000,
    proto: int = 6,
) -> str:
    # Field order mirrors HEADER exactly:
    # Flow ID, Source IP, Src Port, Destination IP, Destination Port, Protocol,
    # Timestamp, Flow Duration, Fwd Pkts, Bwd Pkts, Fwd Bytes, Bwd Bytes, Label
    seq = abs(hash((src, ts, label))) % 100_000
    return (
        f"flow-{seq},{src},1000,{dst},{dst_port},{proto},"
        f"{ts},{duration_us},10,8,1200,5400,{label}\n"
    )


@pytest.fixture()
def cicids_csv(tmp_path: Path) -> Path:
    path = tmp_path / "GeneratedLabelledFlows.csv"
    lines = [HEADER]
    for i in range(30):
        lines.append(_row("192.168.10.21", "192.168.10.50", f"03/07/2017 08:{i:02d}:00", "BENIGN"))
    for i in range(10):
        lines.append(
            _row(
                "203.0.113.77",
                "192.168.10.50",
                f"03/07/2017 09:{i:02d}:00",
                "PortScan",
                dst_port=22 + i,
            )
        )
    lines.append(
        _row("203.0.113.77", "192.168.10.50", "NOT-A-DATE", "PortScan")
    )  # bad ts -> skipped
    path.write_text("".join(lines), encoding="utf-8")
    return path


def test_prepare_produces_valid_sorted_scenario(cicids_csv: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    meta = prep.prepare([cicids_csv], out_dir, "test_cicids", max_events=100)

    scenario = out_dir / "test_cicids.jsonl"
    assert scenario.exists() and (out_dir / "test_cicids.meta.json").exists()

    events = [parse_event_payload(line) for line in scenario.read_text().splitlines()]
    assert len(events) == meta["rows_written"] == 40  # 30 benign + 10 attack
    assert meta["labels"] == {"attack": 10, "benign": 30}
    assert meta["dropped_unusable"] == 0
    # the NOT-A-DATE row was rejected at CSV-scan stage, before sampling
    assert meta["skipped_bad_timestamp"] == 1

    timestamps = [e.ts for e in events]
    assert timestamps == sorted(timestamps), "scenario must be time-sorted"

    attacks = [e for e in events if e.ground_truth_label]
    assert len(attacks) == 10
    assert all(str(e.src_entity.identifier) == "203.0.113.77" for e in attacks)

    sample = attacks[0].features
    assert sample.dst_port == 22 and sample.conn_state == "UNK"


def test_prepare_is_deterministic_and_idempotent(cicids_csv: Path, tmp_path: Path) -> None:
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    prep.prepare([cicids_csv], out_a, "det", max_events=100)
    prep.prepare([cicids_csv], out_b, "det", max_events=100)
    assert (out_a / "det.jsonl").read_text() == (out_b / "det.jsonl").read_text()


def test_prepare_rejects_variant_without_ips(tmp_path: Path) -> None:
    path = tmp_path / "MachineLearningCVE.csv"
    path.write_text(" Destination Port,Flow Duration, Label\n80,1000,BENIGN\n", encoding="utf-8")
    with pytest.raises(prep.PrepareError, match="GeneratedLabelledFlows"):
        prep.prepare([path], tmp_path / "out", "noip", max_events=10)


def test_budget_respects_max_events(tmp_path: Path) -> None:
    path = tmp_path / "big.csv"
    lines = [HEADER]
    lines += [_row("10.0.0.1", "10.0.0.9", "05/07/2017 10:00:00", "BENIGN") for _ in range(200)]
    lines += [_row("10.9.9.9", "10.0.0.9", "05/07/2017 11:00:00", "DoS") for _ in range(60)]
    path.write_text("".join(lines), encoding="utf-8")

    meta = prep.prepare([path], tmp_path / "out", "budget", max_events=100)
    total = meta["labels"]["attack"] + meta["labels"]["benign"]
    assert total == 100
    # attacks get priority up to 60% of budget; benign fills the rest
    assert meta["labels"]["attack"] == 60
    assert meta["labels"]["benign"] == 40


def test_jsonl_lines_parse_again_with_stable_ids(cicids_csv: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    prep.prepare([cicids_csv], out_dir, "stable", max_events=100)
    ids = []
    for line in (out_dir / "stable.jsonl").read_text().splitlines():
        payload = json.loads(line)
        event = CanonicalEvent(**payload)
        ids.append(event.event_id)
    assert len(ids) == len(set(ids)), "flow-tuple uuid5 must be unique per distinct flow"
