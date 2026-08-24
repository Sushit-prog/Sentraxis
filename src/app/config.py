"""Application settings loaded exclusively from environment variables (.env supported)."""

from functools import lru_cache
from typing import Literal

import structlog
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = structlog.get_logger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Literal["dev", "demo", "prod"] = "dev"
    log_level: str = "INFO"
    database_url: SecretStr  # required: fail-fast at startup when missing
    redis_url: str  # required: fail-fast at startup when missing

    event_batch_size: int = Field(default=500, ge=1)
    replay_default_eps: int = Field(default=1000, ge=0)

    # Detection engine (M2)
    det_batch_size: int = Field(default=2000, ge=1)
    det_poll_interval_s: float = Field(default=1.0, gt=0)
    det_window_seconds: int = Field(default=60, ge=1)
    det_rate_z_trigger: float = Field(default=4.0, gt=0)
    det_rate_z_cap: float = Field(default=12.0, gt=0)
    det_rate_min_history: int = Field(default=20, ge=1)
    det_port_threshold: int = Field(default=10, ge=2)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        upper = value.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR"}
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got '{value}'")
        return upper


@lru_cache
def get_settings() -> Settings:
    settings = Settings()  # type: ignore[call-arg]
    logger.debug("settings_loaded", app_env=settings.app_env)
    return settings
