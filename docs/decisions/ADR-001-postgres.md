# ADR-001: PostgreSQL as primary datastore

## Context
The platform stores relational operational state (entities, detections, incidents,
actions, audit ledger) plus semi-structured telemetry payloads. Future milestones
require time-partitioned event storage and transactional guarantees around
incident/action state transitions.

## Options
- PostgreSQL 16: relational integrity, JSONB, declarative partitioning, mature tooling.
- MongoDB / document DBs: schemaless flexibility, weaker cross-entity transactional story.
- TimescaleDB: purpose-built time-series features on Postgres.

## Decision
PostgreSQL 16. JSONB covers flexible telemetry payloads; native RANGE partitioning
covers event volume growth.

## Trade-offs
Manual partition management later; TimescaleDB's continuous aggregates would reduce
custom analytics code, but its managed-service availability and licensing add
constraints not justified at current scale (<100M events projected). Revisit if
event ingestion exceeds single-node Postgres comfort zone.

## Amendment (M1): table partitioning DEFERRED
Original decision implied RANGE-partitioning `events` from the start. Implementation
review changed this: (a) PostgreSQL 16 does not support foreign keys *referencing*
partitioned tables, so `detections -> events` referential integrity would be lost —
the incident evidence chain depends on it; (b) projected volume (<10M rows across all
scenarios) is comfortably served by plain tables plus `(src_entity_id, ts)` and `ts`
indexes.

Revisit triggers: sustained ingestion >5k events/sec, retention-driven pruning of
hundreds of millions of rows, or PG18+ adoption (FK-to-partitioned support). Until
then the schema stays simple; this deferral costs nothing measurable today.

