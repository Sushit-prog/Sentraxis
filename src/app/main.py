"""Application entrypoint: app factory + uvicorn module-level instance."""

from fastapi import FastAPI

from app.api.health import router as health_router
from app.config import Settings, get_settings
from app.observability.logging import configure_logging
from app.persistence.db import create_db_engine, create_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI application. Dependencies are attached to app.state."""
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Cyber Resilience Platform",
        version="0.1.0",
        description="Agentic detection-and-response for critical infrastructure (PS #7).",
    )
    app.state.settings = settings
    app.state.engine = create_db_engine(settings)  # lazy: no connection until used
    app.state.session_factory = create_session_factory(app.state.engine)
    app.include_router(health_router)
    return app


app = create_app()
