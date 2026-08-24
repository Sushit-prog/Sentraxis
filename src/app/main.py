"""Application entrypoint: app factory + uvicorn module-level instance."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from app.api.actions import router as actions_router
from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.api.metrics import router as metrics_router
from app.config import Settings, get_settings
from app.observability.logging import configure_logging
from app.persistence.db import create_db_engine, create_session_factory

logger = structlog.get_logger(__name__)


def _seed_admin_if_configured(settings: Settings) -> None:
    """Create the initial admin account in dev/demo profiles.

    Seeding happens only when ADMIN_PASSWORD is explicitly set and the users
    table is empty — production clusters provision users via a seeder script
    instead of env defaults.
    """
    if settings.app_env not in ("dev", "demo"):
        return
    password = settings.admin_password.get_secret_value()
    if not password:
        return

    from argon2 import PasswordHasher

    from app.persistence.models import UserRow

    session_factory = create_session_factory(create_db_engine(settings))
    with session_factory() as session, session.begin():
        if session.query(UserRow).count() > 0:
            return
        session.add(
            UserRow(
                email=settings.admin_email,
                password_hash=PasswordHasher().hash(password),
                role="admin",
            )
        )
    logger.info("admin_user_seeded", email=settings.admin_email)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    try:
        _seed_admin_if_configured(settings)
    except Exception as exc:  # noqa: BLE001 - seeding must never block startup
        logger.warning("admin_seeding_skipped", error=str(exc)[:200])
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application. Dependencies are attached to app.state."""
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Cyber Resilience Platform",
        version="0.1.0",
        description="Agentic detection-and-response for critical infrastructure (PS #7).",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = create_db_engine(settings)  # lazy: no connection until used
    app.state.session_factory = create_session_factory(app.state.engine)
    app.include_router(health_router)
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(actions_router, prefix="/api/v1")
    app.include_router(metrics_router, prefix="/api/v1")
    return app


app = create_app()
