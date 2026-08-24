"""structlog JSON logging configuration with sensitive-value redaction."""

import logging
import sys
from typing import Any

import structlog

_SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
    "database_url",
}

_REDACTED = "***REDACTED***"


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (_REDACTED if str(k).lower() in _SENSITIVE_KEYS else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(item) for item in value]
    return value


def redact_sensitive(
    logger: Any, method_name: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """structlog processor: replace values of sensitive keys before serialization."""
    for key in list(event_dict.keys()):
        if str(key).lower() in _SENSITIVE_KEYS:
            event_dict[key] = _REDACTED
        else:
            event_dict[key] = _redact_value(event_dict[key])
    return event_dict


def configure_logging(log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_sensitive,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
