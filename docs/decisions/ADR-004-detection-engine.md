# ADR-004: Detection engine — pure detectors over canonical batches, relational state

## Context
M2 adds behavioral anomaly detection. The design must keep the deterministic
spine testable, avoid streaming-framework lock-in, and make detector outputs
evaluable against labeled scenarios. An earlier draft of M1 planned an
`activity_profiles` table as "groundwork"; it was dropped because a table with
no reader is speculative schema.

## Options
- Stream-processing framework (Faust/Bytewax/Kafka Streams): windowing and
  scale for free; heavy dependency + operational surface unjustified below
  thousands of events/sec.
- LLM-based anomaly judgment in the hot path: non-deterministic cost/latency on
  every event; reserved instead for correlation of *clustered* detections.
- Pure Python detector functions over canonical event batches, with per-entity
  statistical state persisted relationally.

## Decision
Detectors are pure functions: `(batch of CanonicalEvent) -> list[Detection]`,
registered in an explicit registry, executed by the existing worker pattern.
Behavioral state (per-entity baselines: rates, peer-group stats, rare-port
sets) lives in Postgres, updated transactionally alongside detections. The
LLM layer stays strictly downstream (correlation), preserving the
"system works with zero model calls" property.

## Trade-offs
No distributed windowing until load demands it (same deferral logic as
ADR-001/002); per-detector state migrations arrive with the first detector in
M2, so the schema grows only when a consumer exists.
