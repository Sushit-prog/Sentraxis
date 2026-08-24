# Ingestion throughput benchmark

Environment: single Windows dev machine, Docker Desktop (WSL2 backend), all five
processes on one host — replay injector CLI → Redis Streams → normalizer worker
(batch=500) → PostgreSQL 16 (JSONB feature payloads). Numbers are end-to-end
wall clock from first XADD to final DB commit, measured by
`scripts/bench_replay.py` (delta-count polling at 250ms).

## Results

| Run | Injector | Events | Elapsed | End-to-end rate |
| --- | --- | ---: | ---: | ---: |
| 1 | per-message XADD | 50,000 | 91.4s | 547 /s |
| 2 | pipelined XADD (batches of 500) | 50,000 | 30.7s | **1,629 /s** |

Run 2 phase breakdown (from logs): injection completed in ~8s (~6,000 events/s
client-side); the normalizer drained the resulting backlog at ~2,200 events/s.
Zero message loss both runs (`events_ingested == events_sent`, dead-letter
stream empty).

## Interpretation

- The stream pipeline (normalize → entity upsert → idempotent batch insert)
  currently saturates around **~2,000–2,500 events/s** on this host. That is
  ~15× the CICIDS2017 daily-average rate and comfortably above every planned
  evaluation workload for M2.
- After the injector fix, the bottleneck moved to where it belongs: durable
  storage writes, not client-side chatter.

## Known optimization levers (deliberately unused now)

- Larger normalizer batches or multiple consumer processes (linear until PG
  write saturation).
- `COPY`-based bulk load instead of parameterized INSERT … ON CONFLICT.
- Redis pipelining depth tuning.

Each lever costs complexity; none is justified while the slowest realistic
scenario replays in under a minute. Re-measure when labeled-correlation golden
sets (M7) multiply replay volume.
