# ADR-005: Detection consumes PostgreSQL by cursor; canonical stream deferred

## Context
The M1 architecture diagram routed normalized events through an
`events:canonical` Redis stream to the detection stage. Implementing that
dual-write (DB insert + stream publish) surfaces exactly-once hazards: a crash
between commit and publish loses events for detectors, while redelivery
publishes duplicates — and streaming state updates (Welford baselines) are NOT
naturally idempotent, unlike the event/detection tables.

## Options
- Canonical stream + consumer groups: uniform topology with ingestion; requires
  watermark bookkeeping per consumer to make baseline updates idempotent, or
  accepting drift on rare replays.
- Database-cursor consumption: detector reads `events WHERE id > cursor ORDER
  BY id LIMIT n`, advancing the cursor inside the same transaction as its
  detections and metric-state writes. Crash-safe by construction; unique
  constraints absorb any reprocessing.

## Decision
Database-cursor consumption for M2. The canonical stream returns when a second
low-latency consumer exists (e.g., response-orchestrator triggers in M5); at
that point publishing can be introduced without schema change.

## Trade-offs
Polling latency (~1s default) instead of push; trivial read load at current
scale. Horizontal scaling of detector workers needs cursor partitioning —
deferred until measured demand exists.
