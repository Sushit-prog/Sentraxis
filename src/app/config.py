"""Application settings loaded exclusively from environment variables (.env supported)."""

from functools import lru_cache
from typing import Any, Literal

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

    # Correlation / LLM agent (M3). Free-tier friendly by construction:
    # providers are tried in order; empty keys drop out of the chain and the
    # system degrades to rule-only correlation.
    llm_provider_order: str = "groq,openrouter,mistral"
    groq_api_key: SecretStr = SecretStr("")
    openrouter_api_key: SecretStr = SecretStr("")
    mistral_api_key: SecretStr = SecretStr("")
    llm_model_groq: str = "openai/gpt-oss-120b"
    llm_model_openrouter: str = "meta-llama/llama-3.3-70b-instruct"
    llm_model_mistral: str = "mistral-small-latest"
    llm_request_timeout_s: float = Field(default=25.0, gt=0)
    llm_min_interval_ms: int = Field(default=2500, ge=0)
    llm_daily_budget: int = Field(default=300, ge=1)
    corr_window_seconds: int = Field(default=600, ge=1)
    corr_batch_size: int = Field(default=1000, ge=1)

    # Response orchestration (M5)
    orch_enabled: bool = True
    orch_poll_interval_s: float = Field(default=2.0, gt=0)
    orch_batch_size: int = Field(default=200, ge=1)
    orch_approval_timeout_min: int = Field(default=15, ge=1)
    orch_min_risk: float = Field(default=0.5, ge=0.0, le=1.0)
    quarantine_hours: int = Field(default=24, ge=1)

    # Auth (M3). The default secret is refused outside dev profiles.
    jwt_secret: SecretStr = SecretStr("dev-insecure-change-me")  # validator blocks this in prod
    jwt_expire_minutes: int = Field(default=480, ge=1)
    admin_email: str = "admin@sentraxis.local"
    admin_password: SecretStr = SecretStr("")

    @field_validator("jwt_secret")
    @classmethod
    def _reject_insecure_jwt_secret(cls, value: SecretStr, info: Any) -> SecretStr:
        if getattr(info, "data", {}).get("app_env") == "prod" and value.get_secret_value() in (
            "",
            "dev-insecure-change-me",
        ):
            raise ValueError("JWT_SECRET must be set to a strong value when APP_ENV=prod")
        return value

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
