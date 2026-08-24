"""Test bootstrap: guarantee required settings exist before app modules are imported.

Unit tests never touch live services; integration tests override URLs explicitly.
"""

import os

os.environ.setdefault("APP_ENV", "dev")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://cyber:cyber@localhost:5433/cyber",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
