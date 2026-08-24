"""AuthN/Z dependencies: JWT bearer extraction + role gates."""

from __future__ import annotations

from collections.abc import Generator
from typing import Annotated, Any, Literal

import jwt as pyjwt
import structlog
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import Settings
from app.persistence.models import UserRow
from app.security import decode_token

logger = structlog.get_logger(__name__)

Role = Literal["admin", "analyst", "approver"]


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def get_db_session(request: Request) -> Generator[Session, None, None]:
    session_factory = request.app.state.session_factory
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


DbDep = Annotated[Session, Depends(get_db_session)]


def get_current_user(
    request: Request,
    db: DbDep,
    settings: SettingsDep,
) -> UserRow:
    """Resolve the UserRow from a Bearer JWT; 401 on any failure."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise _unauthorized()
    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token, settings)
    except pyjwt.PyJWTError as exc:
        logger.info("jwt_rejected", error=str(exc))
        raise _unauthorized("Invalid or expired token") from exc

    email = payload.get("sub")
    if not isinstance(email, str):
        raise _unauthorized("Invalid token subject")

    user = db.query(UserRow).filter(UserRow.email == email, UserRow.disabled.is_(False)).first()
    if user is None:
        raise _unauthorized("Unknown user")
    return user


CurrentUser = Annotated[UserRow, Depends(get_current_user)]


def require_roles(*allowed: Role) -> Any:
    """Dependency factory: gate an endpoint behind one of the given roles."""

    def dependency(user: CurrentUser) -> UserRow:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed)}",
            )
        return user

    return dependency


AdminUser = Annotated[UserRow, Depends(require_roles("admin"))]
AnalystOrAdmin = Annotated[UserRow, Depends(require_roles("admin", "analyst"))]
AnyRole = Annotated[UserRow, Depends(require_roles("admin", "analyst", "approver"))]
