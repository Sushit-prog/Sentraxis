"""Shared integration-test database provisioning.

Every integration-test entry point MUST route through ``get_it_settings`` /
``ensure_test_database`` so the isolated ``cyber_test`` database exists and is
migrated regardless of which test file executes first.
"""

import os

from sqlalchemy import text

from app.config import Settings

TEST_DB = "cyber_test"


def base_env_settings() -> Settings:
    redis_base = os.environ["REDIS_URL"].rsplit("/", 1)[0]
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=os.environ["DATABASE_URL"],
        redis_url=f"{redis_base}/1",
    )


def test_database_url(settings: Settings) -> str:
    return settings.database_url.get_secret_value().rsplit("/", 1)[0] + f"/{TEST_DB}"


def ensure_test_database(settings: Settings) -> str:
    """Create cyber_test if absent, migrate to head; returns its URL."""
    from alembic import command
    from alembic.config import Config

    admin = __import__("sqlalchemy").create_engine(
        settings.database_url.get_secret_value().rsplit("/", 1)[0] + "/postgres",
        isolation_level="AUTOCOMMIT",
    )
    with admin.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": TEST_DB}
        ).first()
        if not exists:
            conn.execute(text(f"CREATE DATABASE {TEST_DB}"))
    admin.dispose()

    test_url = test_database_url(settings)
    old_env = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = test_url
    try:
        cfg = Config("alembic.ini")
        cfg.set_main_option("script_location", "migrations")
        command.upgrade(cfg, "head")
    finally:
        if old_env is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = old_env
    return test_url
