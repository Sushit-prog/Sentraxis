# ADR-002: Redis Streams as the event backbone

## Context
The pipeline is streaming by design: replay injection → normalization → detection
→ correlation → response orchestration. Requires consumer groups, at-least-once
delivery with crash recovery (pending entry reclaim), and later reuse as cache +
rate-limiter backend for the LLM gateway.

## Options
- Kafka: gold standard durability/throughput; operational weight (broker, ZK/KRaft)
  unjustified below thousands of events/sec.
- RabbitMQ: solid queuing; no natural consumer-group offset semantics, no secondary
  use as cache/rate limiter.
- Postgres SKIP LOCKED queue: zero extra infra; mixes hot queue polling with
  analytical/event storage in one DB; no pending-entry semantics.
- Celery + broker: hides worker internals behind framework magic; harder to teach,
  debug, and audit precisely.

## Decision
Redis Streams with named consumer groups, explicit ACK, and XAUTOCLAIM idle-reclaim
for crashed workers. Redis additionally serves the LLM gateway's rate limiting and
response caching.

## Trade-offs
Weaker durability than Kafka (AOF config mitigates), single-node memory bounds.
Both acceptable at projected scale (<few k events/sec); stream keys already map to
future topic boundaries if migration ever becomes necessary.
