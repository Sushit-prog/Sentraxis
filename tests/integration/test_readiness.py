"""Integration tests: require live postgres + redis.

Run with:
    docker compose up -d postgres redis
    uv run pytest -m integration
"""

import os

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

pytestmark = [pytest.mark.integration]


def _live_settings() -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=os.environ["DATABASE_URL"],
        redis_url=os.environ["REDIS_URL"],
    )


def test_readyz_ok_when_dependencies_up() -> None:
    client = TestClient(create_app(_live_settings()))
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.json()
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["postgres"] == "ok"
    assert body["checks"]["redis"] == "ok"


def test_readyz_503_with_broken_redis_but_postgres_ok() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=os.environ["DATABASE_URL"],
        redis_url="redis://localhost:59999/0",  # nothing listens here
    )
    client = TestClient(create_app(settings))
    resp = client.get("/readyz")
    assert resp.status_code == 503, resp.json()
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["redis"] == "error"
    assert body["checks"]["postgres"] == "ok"


def test_readyz_503_with_broken_postgres_but_redis_ok() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url="postgresql+psycopg://cyber:cyber@localhost:59998/cyber",
        redis_url=os.environ["REDIS_URL"],
    )
    client = TestClient(create_app(settings))
    resp = client.get("/readyz")
    assert resp.status_code == 503, resp.json()
    body = resp.json()
    assert body["checks"]["postgres"] == "error"
    assert body["checks"]["redis"] == "ok"
