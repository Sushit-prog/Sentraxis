# ADR-003: Single deployable, multiple processes; sync data layer

## Context
Solo engineer building toward a startup-grade system. Temptations: microservice
split, async SQLAlchemy everywhere.

## Options
- Microservices per stage: independent scaling/deploy isolation; distributed-systems
  overhead (contracts, tracing, deploys) unjustified now.
- Single image, N worker processes + API process: one codebase, one deploy artifact,
  process-level separation of concerns via Redis Streams boundaries.
- Async SQLAlchemy + asyncpg: higher raw concurrency; adds lifecycle complexity,
  harder debugging, marginal benefit below a few thousand events/sec.

## Decision
One Docker image run as several processes (api, workers) communicating through
Redis Streams. Sync SQLAlchemy 2.0 with psycopg; FastAPI endpoints that touch the
DB are plain `def` (threadpool).

## Trade-offs
Vertical scale limit before async rewrite or sharding is needed — acceptable and
measurable. Process boundaries already drawn along stream interfaces keep the
future extraction of services cheap if load ever demands it.
