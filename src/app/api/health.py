"""Health and readiness endpoints."""

import redis
import structlog
from fastapi import APIRouter, Request
from sqlalchemy import create_engine, text
from starlette.responses import JSONResponse

from app.config import Settings

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["health"])

_CHECK_TIMEOUT_SECONDS = 2


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness: process is up. No dependency checks."""
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request) -> JSONResponse:
    """Readiness: postgres + redis reachable within timeout.

    Uses its own short-lived connections; never the request-scoped DB session.
    """
    settings: Settings = request.app.state.settings
    checks: dict[str, str] = {"postgres": "error", "redis": "error"}

    checks["postgres"] = _check_postgres(settings)
    checks["redis"] = _check_redis(settings)

    ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if ok else 503,
        content={"status": "ready" if ok else "not_ready", "checks": checks},
    )


def _check_postgres(settings: Settings) -> str:
    engine = None
    try:
        engine = create_engine(
            settings.database_url.get_secret_value(),
            pool_pre_ping=False,
            connect_args={"connect_timeout": _CHECK_TIMEOUT_SECONDS},
        )
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:  # readiness must never raise
        logger.warning("readiness_check_failed", component="postgres", error=str(exc))
        return "error"
    finally:
        if engine is not None:
            engine.dispose()


def _check_redis(settings: Settings) -> str:
    client = None
    try:
        client = redis.Redis.from_url(
            settings.redis_url,
            socket_connect_timeout=_CHECK_TIMEOUT_SECONDS,
            socket_timeout=_CHECK_TIMEOUT_SECONDS,
        )
        client.ping()
        return "ok"
    except Exception as exc:  # readiness must never raise
        logger.warning("readiness_check_failed", component="redis", error=str(exc))
        return "error"
    finally:
        if client is not None:
            client.close()
