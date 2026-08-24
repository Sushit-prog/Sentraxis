"""Stream and group naming. Single source of truth for all workers."""

RAW_STREAM = "events:raw"
DEAD_STREAM = "events:dead"
NORMALIZER_GROUP = "normalizers"

CLAIM_IDLE_MS = 60_000  # pending entries idle longer than this get reclaimed
READ_BLOCK_MS = 5_000  # XREADGROUP blocking wait when idle

CHECKPOINT_EVERY = 500  # injector: persist resume offset every N messages
XADD_BATCH = 500  # injector: pipeline this many XADDs per round trip
