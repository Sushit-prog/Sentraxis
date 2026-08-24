"""Integration test fixtures.

Isolation contract: tests run against a DEDICATED `cyber_test` database on the
same Postgres server — created and migrated automatically regardless of which
test file executes first (see tests/integration/_db.py). The dev/demo database
(`cyber`) is never touched by the suite; Redis uses logical db /1 to stay clear
of live workers.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.main import create_app  # noqa: F401 (used by app_client fixture)
from app.persistence.db import create_db_engine, create_session_factory
from app.persistence.models import UserRow
from app.security import hash_password  # noqa: F401 (fixtures below)
from app.workers.connections import create_redis
from tests.integration._db import base_env_settings, ensure_test_database

ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "test-admin-pass"
USER_EMAIL = "approver@test.local"


@pytest.fixture(scope="session")
def it_settings() -> Settings:
    base = base_env_settings()
    test_url = ensure_test_database(base)
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=test_url,
        redis_url=base.redis_url,
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
    """Full fresh slate: telemetry + every derived table (test DB only)."""
    with session_factory() as session:
        session.execute(
            text(
                "TRUNCATE events, entities, detections, entity_metric_state,"
                " worker_cursors, incidents, incident_detections, llm_calls,"
                " actions, playbooks, audit_log RESTART IDENTITY CASCADE"
            )
        )
        session.commit()
    yield session_factory


# ---- shared API test fixtures ------------------------------------------------


@pytest.fixture(scope="module")
def _module_test_url():
    return ensure_test_database(base_env_settings())


@pytest.fixture(scope="module")
def _module_session_factory(_module_test_url: str):
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=_module_test_url,
        redis_url=base_env_settings().redis_url,
    )
    return create_session_factory(create_db_engine(settings))


@pytest.fixture(scope="module")
def app_client(_module_session_factory, _module_test_url: str):
    """One authenticated API instance per module; admin/approver provisioned."""
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url=_module_test_url,
        redis_url=base_env_settings().redis_url,
        admin_password=ADMIN_PASSWORD,
        admin_email=ADMIN_EMAIL,
        app_env="dev",
    )
    # idempotent provisioning across runs (users table survives truncations)
    with _module_session_factory() as s, s.begin():
        s.query(UserRow).filter(UserRow.email.in_([ADMIN_EMAIL, USER_EMAIL])).delete(
            synchronize_session=False
        )
        s.add(UserRow(email=ADMIN_EMAIL, password_hash=hash_password(ADMIN_PASSWORD), role="admin"))
        s.add(
            UserRow(email=USER_EMAIL, password_hash=hash_password("approver-pass"), role="approver")
        )

    application = create_app(settings)
    with TestClient(application) as client:
        yield client


def _base_env_settings_alias():  # kept for backward-compat imports in tests
    return base_env_settings()
