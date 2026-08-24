"""Shared fixtures for integration tests.

Redis DB index /1 isolates tests from the live normalizer service, which
consumes db 0 inside the compose network. PostgreSQL is shared but safe:
nothing writes to it unless someone replays into stream db 0 concurrently.
"""

import os

import pytest

from app.config import Settings
from app.persistence.db import create_db_engine, create_session_factory
from app.workers.connections import create_redis


@pytest.fixture(scope="session")
def it_settings() -> Settings:
    redis_url = os.environ["REDIS_URL"].rsplit("/", 1)[0]
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=os.environ["DATABASE_URL"],
        redis_url=f"{redis_url}/1",
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
    """Truncate operational tables before each test."""
    from sqlalchemy import text

    with session_factory() as session:
        session.execute(text("TRUNCATE events, entities RESTART IDENTITY CASCADE"))
        session.commit()
    yield session_factory
