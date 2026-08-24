import pytest
from pydantic import ValidationError

from app.config import Settings


def test_missing_database_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_missing_redis_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_settings_load_from_explicit_values() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url="postgresql+psycopg://user:pass@host:5432/db",
        redis_url="redis://localhost:6379/0",
    )
    assert settings.app_env == "dev"
    assert settings.log_level == "INFO"
    # SecretStr keeps credentials out of logs/repr
    assert "pass" not in repr(settings.database_url)
    assert settings.database_url.get_secret_value().startswith("postgresql+psycopg://")


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,  # type: ignore[call-arg]
            database_url="postgresql+psycopg://user:pass@host:5432/db",
            redis_url="redis://localhost:6379/0",
            log_level="VERBOSE",
        )


def test_log_level_normalized_to_uppercase() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url="postgresql+psycopg://user:pass@host:5432/db",
        redis_url="redis://localhost:6379/0",
        log_level="debug",
    )
    assert settings.log_level == "DEBUG"


def test_prod_rejects_default_jwt_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,  # type: ignore[call-arg]
            database_url="postgresql+psycopg://u:p@h:5432/d",
            redis_url="redis://localhost:6379/0",
            app_env="prod",
        )


def test_dev_allows_default_jwt_secret() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        database_url="postgresql+psycopg://u:p@h:5432/d",
        redis_url="redis://localhost:6379/0",
        app_env="dev",
    )
    assert settings.jwt_secret.get_secret_value() == "dev-insecure-change-me"
