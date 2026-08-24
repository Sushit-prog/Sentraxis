"""Generate a synthetic bulk scenario for pipeline throughput benchmarking.

Schema-valid network flows with a realistic shape: mostly benign web/DNS
traffic across a small host pool, punctuated by attack bursts (SYN sweeps,
floods). Deterministic under a fixed seed so benchmarks are reproducible.

NOTE: synthetic flows validate the *pipeline*, not detection realism — real
CICIDS2017 data enters via scripts/prepare_cicids.py.
"""

import argparse
import random
import uuid
from datetime import UTC, datetime
from pathlib import Path

from app.domain.events import (
    CanonicalEvent,
    EntityRef,
    EntityType,
    EventSource,
    NetworkFlowFeatures,
    Protocol,
)

BENIGN_HOSTS = ["192.168.10.21", "192.168.10.33", "192.168.10.44"]
SERVER = "192.168.10.50"
ATTACKERS = ["203.0.113.77", "198.51.100.9"]
WEB_PORTS = [80, 443]
SCAN_PORTS = [
    21,
    22,
    23,
    25,
    53,
    110,
    143,
    445,
    1433,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    9200,
]

BASE_TS = 1785000000.0  # fixed epoch; determinism over wall-clock realism


def _flow(
    seq: int,
    ts: float,
    src: str,
    dst: str,
    *,
    dst_port: int,
    label: bool,
    duration: float,
    src_bytes: int,
    dst_bytes: int,
    src_pkts: int,
    dst_pkts: int,
    state: str,
    protocol: str = "tcp",
    seed: int = 0,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid.uuid5(uuid.NAMESPACE_URL, f"sentraxis:bulk:{seed}:{seq}"),
        source=EventSource.network_flow,
        ts=datetime.fromtimestamp(ts, tz=UTC),
        src_entity=EntityRef(type=EntityType.host, identifier=src),
        dst_entity=EntityRef(type=EntityType.host, identifier=dst),
        ground_truth_label=label,
        features=NetworkFlowFeatures(
            protocol=Protocol(protocol),
            src_port=40000 + (seq % 20000),
            dst_port=dst_port,
            duration_s=round(duration, 6),
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            src_pkts=src_pkts,
            dst_pkts=dst_pkts,
            conn_state=state,
        ),
    )


def generate(total: int, attack_ratio: float, seed: int) -> list[CanonicalEvent]:
    rng = random.Random(seed)
    n_attacks = int(total * attack_ratio)
    events: list[CanonicalEvent] = []

    seq = 0
    for i in range(total - n_attacks):
        host = rng.choice(BENIGN_HOSTS)
        port = rng.choice(WEB_PORTS) if rng.random() < 0.85 else 53
        proto = "udp" if port == 53 else "tcp"
        events.append(
            _flow(
                seq,
                BASE_TS + i / 50.0,
                host,
                SERVER,
                dst_port=port,
                label=False,
                duration=rng.uniform(0.02, 4.0),
                src_bytes=rng.randint(80, 5000),
                dst_bytes=rng.randint(150, 90_000),
                src_pkts=rng.randint(2, 60),
                dst_pkts=rng.randint(2, 80),
                state="SF",
                protocol=proto,
                seed=seed,
            )
        )
        seq += 1

    # Attack bursts interleaved in the second half of the window.
    burst_start = BASE_TS + (total - n_attacks) / 50.0 * 0.5
    attacker_cycle = 0
    for i in range(n_attacks):
        attacker = ATTACKERS[i % len(ATTACKERS)]
        if i % 50 == 0:
            attacker_cycle += 1
        # SYN sweep pattern: rapid successive ports, RST/S0 responses
        events.append(_flow_scan(seq, burst_start + i * 0.01, attacker, attacker_cycle, i, seed))
        seq += 1

    events.sort(key=lambda e: e.ts)
    return events


def _flow_scan(
    seq: int, ts: float, attacker: str, cycle: int, i: int, seed: int = 0
) -> CanonicalEvent:
    return _flow(
        seq,
        ts,
        attacker,
        SERVER,
        dst_port=SCAN_PORTS[(i + cycle) % len(SCAN_PORTS)],
        label=True,
        duration=0.001 if i % 3 else 0.12,
        src_bytes=0 if i % 3 else 74,
        dst_bytes=0,
        src_pkts=1 if i % 3 else 2,
        dst_pkts=1,
        state="RST" if i % 3 else "S0",
        seed=seed,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate bulk benchmark scenario")
    parser.add_argument("--events", type=int, default=50_000)
    parser.add_argument("--attack-ratio", type=float, default=0.1)
    parser.add_argument("--output", type=Path, default=Path("scenarios/bulk_bench.jsonl"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    events = generate(args.events, args.attack_ratio, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as fh:
        for event in events:
            fh.write(event.model_dump_json() + "\n")

    attacks = sum(1 for e in events if e.ground_truth_label)
    print(f"wrote {len(events)} events ({attacks} labeled attack) -> {args.output}")


if __name__ == "__main__":
    main()
