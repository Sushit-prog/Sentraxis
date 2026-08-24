"""Auth endpoints: password -> JWT exchange."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.api.deps import DbDep, SettingsDep
from app.persistence.models import UserRow
from app.security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@router.post("/token", response_model=TokenResponse)
def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbDep,
    settings: SettingsDep,
) -> TokenResponse:
    user: UserRow | None = (
        db.query(UserRow)
        .filter(UserRow.email == form.username, UserRow.disabled.is_(False))
        .first()
    )
    if user is None or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(subject=user.email, role=user.role, settings=settings)
    return TokenResponse(access_token=token, role=user.role)
