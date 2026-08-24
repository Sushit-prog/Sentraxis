"""Prepare labeled scenario JSONL files from CICIDS2017-style CSV exports.

Expects the *GeneratedLabelledFlows* variant of CICIDS-2017 (the one containing
Source/Destination IP and Timestamp columns). The MachineLearningCVE variant
lacks IP addresses and is rejected explicitly — entity identity is mandatory.

Behavior:
- Streams the CSV (bounded memory), normalizes headers, maps a subset of flow
  features onto the canonical event contract.
- Sampling: keeps up to ``--max-attacks`` labeled attack rows (reservoir,
  seeded) and fills the remaining budget with benign rows, so attack evidence
  is never drowned out by the ~80% benign majority of the raw dataset.
- Deterministic event ids: UUIDv5 over the flow tuple -> identical rows dedupe
  naturally across runs/replays.
- Emits <output>/<name>.jsonl (timestamp-sorted) plus <name>.meta.json with
  provenance and label statistics.

Rows with unparseable timestamps are counted and skipped, never silently kept.
"""

import argparse
import csv
import json
import random
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from app.domain.events import (
    CanonicalEvent,
    EntityRef,
    EntityType,
    EventSource,
    NetworkFlowFeatures,
    Protocol,
)

logger = structlog.get_logger(__name__)

# Stable namespace so the same flow always maps to the same event_id.
EVENT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "sentraxis:cicids2017:v1")

PROTOCOL_MAP = {6: "tcp", 17: "udp", 1: "icmp", 0: "icmp"}

TS_FORMATS = ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S")

REQUIRED_COLUMNS = {"source ip", "destination ip", "timestamp", "label"}

COLUMN_ALIASES = {
    "destination port": "dst_port",
    "flow duration": "duration_us",
    "total fwd packets": "src_pkts",
    "total backward packets": "dst_pkts",
    "total length of fwd packets": "src_bytes",
    "total length of bwd packets": "dst_bytes",
    "protocol": "protocol",
    "src port": "src_port",
    "source port": "src_port",
}


class PrepareError(Exception):
    """Fatal input problem: bad variant, missing columns, unusable file."""


def _parse_timestamp(raw: str) -> datetime | None:
    value = raw.strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _to_int(raw: str, default: int = 0) -> int:
    try:
        return int(float(raw))
    except (ValueError, TypeError):
        return default


def _read_rows(path: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Stream one CSV; returns (kept_raw_rows, stats). Kept rows are sampled."""
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise PrepareError(f"{path.name}: empty CSV")
        headers = {h.strip().lower() for h in reader.fieldnames}
        missing = REQUIRED_COLUMNS - headers
        if missing:
            raise PrepareError(
                f"{path.name}: missing required columns {sorted(missing)}. "
                "Use the GeneratedLabelledFlows variant (it contains IPs/Timestamps); "
                "MachineLearningCVE CSVs do not carry entity identity."
            )
        alias = {h.strip().lower(): h for h in reader.fieldnames}

        rng = random.Random(20260824)  # deterministic sampling across runs
        attacks: list[dict[str, str]] = []
        benign: list[dict[str, str]] = []
        seen_attack = 0
        seen_benign = 0
        skipped_ts = 0
        label_counts: Counter[str] = Counter()

        for row in reader:
            label = (row.get(alias["label"]) or "").strip()
            if not label:
                continue
            label_counts[label] += 1
            if _parse_timestamp(row[alias["timestamp"]] if alias.get("timestamp") else "") is None:
                skipped_ts += 1
                continue

            # Reservoir sampling per class: bounded memory, deterministic order-independent.
            is_attack = label.upper() != "BENIGN"
            if is_attack:
                seen_attack += 1
                if len(attacks) < _MAX_ATTACK_RESERVOIR:
                    attacks.append(row)
                else:
                    j = rng.randint(0, seen_attack - 1)
                    if j < _MAX_ATTACK_RESERVOIR:
                        attacks[j] = row
            else:
                seen_benign += 1
                if len(benign) < _MAX_BENIGN_RESERVOIR:
                    benign.append(row)
                else:
                    j = rng.randint(0, seen_benign - 1)
                    if j < _MAX_BENIGN_RESERVOIR:
                        benign[j] = row

    stats = {
        "seen_attack": seen_attack,
        "seen_benign": seen_benign,
        "skipped_bad_timestamp": skipped_ts,
        "label_counts": dict(label_counts),
        "attack_reservoir": len(attacks),
        "benign_reservoir": len(benign),
    }

    def _normalized(row: dict[str, str], class_label: str) -> dict[str, str]:
        # Re-key to stripped/lowercase + COLUMN_ALIASES names so downstream
        # lookups are immune to the dataset's space-padded headers.
        out = {COLUMN_ALIASES.get(low, low): row[orig] for low, orig in alias.items()}
        out["label"] = class_label
        return out

    rows = [
        _normalized(r, "attack" if (r.get(alias["label"]) or "").upper() != "BENIGN" else "benign")
        for r in attacks + benign
    ]
    return rows, stats


_MAX_ATTACK_RESERVOIR = 200_000
_MAX_BENIGN_RESERVOIR = 400_000


def _row_to_event(row: dict[str, str]) -> CanonicalEvent | None:
    get = lambda key: row.get(key, "")  # noqa: E731 - local shorthand over aliased keys
    ts = _parse_timestamp(get("timestamp"))
    if ts is None:
        return None
    src_ip = get("source ip").strip()
    dst_ip = get("destination ip").strip()
    if not src_ip or not dst_ip:
        return None

    duration_us = _to_int(get("duration_us"))
    src_port = _to_int(get("src_port"))
    dst_port = _to_int(get("dst_port"))
    protocol_num = _to_int(get("protocol"), default=6)
    flow_tuple = (
        f"{src_ip}|{dst_ip}|{ts.isoformat()}|{src_port}|{dst_port}|"
        f"{duration_us}|{get('src_bytes')}|{get('dst_bytes')}"
    )

    return CanonicalEvent(
        event_id=uuid.uuid5(EVENT_NAMESPACE, flow_tuple),
        source=EventSource.network_flow,
        ts=ts,
        src_entity=EntityRef(type=EntityType.host, identifier=src_ip),
        dst_entity=EntityRef(type=EntityType.host, identifier=dst_ip),
        ground_truth_label=row["label"] == "attack",
        features=NetworkFlowFeatures(
            protocol=Protocol(PROTOCOL_MAP.get(protocol_num, "tcp")),
            src_port=min(max(src_port, 0), 65535),
            dst_port=min(max(dst_port, 0), 65535),
            duration_s=round(duration_us / 1_000_000, 6),
            src_bytes=_to_int(get("src_bytes")),
            dst_bytes=_to_int(get("dst_bytes")),
            src_pkts=_to_int(get("src_pkts")),
            dst_pkts=_to_int(get("dst_pkts")),
            conn_state="UNK",
        ),
    )


def prepare(
    input_paths: list[Path], output_dir: Path, name: str, max_events: int
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    all_rows: list[tuple[datetime, CanonicalEvent]] = []
    totals: Counter[str] = Counter()
    sources: list[str] = []
    csv_stats: dict[str, Any] = {}

    for path in input_paths:
        rows, stats = _read_rows(path)
        sources.append(path.name)
        csv_stats[path.name] = stats
        logger.info("csv_scanned", file=path.name, **stats)

        # Class-proportional trim toward the global budget: attacks first (they
        # carry evaluation signal), benign fills the remainder.
        attack_rows = [r for r in rows if r["label"] == "attack"][: int(max_events * 0.6)]
        benign_budget = max_events - len(attack_rows)
        benign_rows = [r for r in rows if r["label"] == "benign"][:benign_budget]

        for row in attack_rows + benign_rows:
            event = _row_to_event(row)
            if event is None:
                totals["dropped_unusable"] += 1
                continue
            all_rows.append((event.ts, event))
            totals["attack" if event.ground_truth_label else "benign"] += 1

    if not all_rows:
        raise PrepareError("no usable rows produced — check input files")

    all_rows.sort(key=lambda pair: pair[0])
    out_path = output_dir / f"{name}.jsonl"
    with out_path.open("w", encoding="utf-8", newline="\n") as fh:
        seen_ids: set[uuid.UUID] = set()
        duplicates = 0
        for _ts, event in all_rows:
            if event.event_id in seen_ids:
                duplicates += 1
                continue
            seen_ids.add(event.event_id)
            fh.write(event.model_dump_json() + "\n")

    meta = {
        "name": name,
        "source_files": sources,
        "rows_written": len(seen_ids),
        "duplicate_flow_tuples_collapsed": duplicates,
        "labels": {"attack": totals["attack"], "benign": totals["benign"]},
        "dropped_unusable": totals["dropped_unusable"],
        "skipped_bad_timestamp": sum(
            int(s.get("skipped_bad_timestamp", 0)) for s in csv_stats.values()
        ),
        "csv_scan_stats": csv_stats,
        "event_id_namespace": str(EVENT_NAMESPACE),
    }
    meta_path = output_dir / f"{name}.meta.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    logger.info("scenario_written", path=str(out_path), **meta)
    return meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert CICIDS2017 CSVs to scenario JSONL")
    parser.add_argument("--input", required=True, nargs="+", type=Path, help="CSV file(s)")
    parser.add_argument("--output-dir", type=Path, default=Path("scenarios"))
    parser.add_argument("--name", required=True, help="Scenario name (file stem)")
    parser.add_argument("--max-events", type=int, default=50_000)
    args = parser.parse_args()

    try:
        prepare(args.input, args.output_dir, args.name, args.max_events)
    except PrepareError as exc:
        logger.error("preparation_failed", error=str(exc))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
