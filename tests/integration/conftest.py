"""Integration test fixtures.

Isolation contract: tests run against a DEDICATED `cyber_test` database on the
same Postgres server — created and migrated automatically once per session.
The dev/demo database (`cyber`) is never touched by the suite; Redis uses
logical db /1 to stay clear of live workers.
"""

import os

import pytest
from sqlalchemy import text
from sqlalchemy.engine import create_engine as sa_create_engine

from app.config import Settings
from app.persistence.db import create_db_engine, create_session_factory
from app.workers.connections import create_redis

TEST_DB = "cyber_test"


def _base_settings() -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=os.environ["DATABASE_URL"],
        redis_url=os.environ["REDIS_URL"].rsplit("/", 1)[0] + "/1",
    )


def _ensure_test_database(settings: Settings) -> None:
    """Create cyber_test if absent and bring its schema to head."""
    admin_url = settings.database_url.get_secret_value().rsplit("/", 1)[0] + "/postgres"
    admin = sa_create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": TEST_DB}
        ).first()
        if not exists:
            conn.execute(text(f"CREATE DATABASE {TEST_DB}"))
    admin.dispose()

    test_url = settings.database_url.get_secret_value().rsplit("/", 1)[0] + f"/{TEST_DB}"

    from alembic import command
    from alembic.config import Config

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


@pytest.fixture(scope="session")
def it_settings() -> Settings:
    settings = _base_settings()
    _ensure_test_database(settings)
    # point everything at the isolated database
    test_url = settings.database_url.get_secret_value().rsplit("/", 1)[0] + f"/{TEST_DB}"
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=test_url,
        redis_url=settings.redis_url,
    )


@pytest.fixture(scope="session")
def session_factory(it_settings: Settings):
    return create_session_factory(create_db_engine(it_settings))


@pytest.fixture()
def rclient(it_settings: Settings):
    client = create_redis(it_settings)
    client.flushdb()
    yield client
    client.flushdb()
    client.close()


@pytest.fixture()
def clean_db(session_factory):
    """Truncate operational tables before each test (test DB only)."""
    with session_factory() as session:
        session.execute(text("TRUNCATE events, entities RESTART IDENTITY CASCADE"))
        session.commit()
    yield session_factory
