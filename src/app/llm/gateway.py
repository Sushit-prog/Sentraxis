"""LLM gateway: OpenAI-compatible providers behind one hardened interface.

Design goals (free-tier reality):
- Provider fallback chain built from whichever API keys are configured.
- Per-provider pacing (min interval) + daily budget counter in Redis; when the
  budget is exhausted the gateway reports it instead of burning calls.
- Response cache keyed on the exact message payload — identical agent inputs
  (e.g., repeated eval runs) cost zero calls.
- Bounded retries with exponential backoff + jitter on 429/5xx/timeouts.
- Transport only: schema validation lives in the correlation agent, so a
  semantically invalid response can be cache-busted and retried deliberately.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.config import Settings

logger = structlog.get_logger(__name__)

PROVIDER_BASE_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "mistral": "https://api.mistral.ai/v1",
}

_RETRY_STATUS = {429, 500, 502, 503, 504}


class GatewayError(Exception):
    """Base gateway failure."""


class AllProvidersFailed(GatewayError):
    """Every configured provider failed after retries."""


class NoProvidersConfigured(GatewayError):
    """No API keys present: caller must use deterministic fallback."""


class BudgetExhausted(GatewayError):
    """Daily call budget spent; deterministic mode until tomorrow."""


@dataclass(slots=True)
class ProviderSpec:
    name: str
    base_url: str
    api_key: str
    model: str


@dataclass(slots=True)
class LlmResult:
    payload: dict[str, Any]
    raw_content: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int
    cache_hit: bool
    cache_key: str


def _cache_key(purpose: str, messages: list[dict[str, str]], chain_signature: str) -> str:
    digest = hashlib.sha256(
        json.dumps(
            {"purpose": purpose, "messages": messages, "chain": chain_signature},
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return f"llm:cache:{digest}"


class LlmGateway:
    def __init__(self, settings: Settings, redis_client: Any | None = None) -> None:
        self.settings = settings
        self.redis = redis_client
        self._cooldown_until: dict[str, float] = {}
        self.providers: list[ProviderSpec] = []
        keys = {
            "groq": settings.groq_api_key.get_secret_value(),
            "openrouter": settings.openrouter_api_key.get_secret_value(),
            "mistral": settings.mistral_api_key.get_secret_value(),
        }
        models = {
            "groq": settings.llm_model_groq,
            "openrouter": settings.llm_model_openrouter,
            "mistral": settings.llm_model_mistral,
        }
        for name in [p.strip() for p in settings.llm_provider_order.split(",") if p.strip()]:
            if keys.get(name):
                self.providers.append(
                    ProviderSpec(
                        name=name,
                        base_url=PROVIDER_BASE_URLS[name],
                        api_key=keys[name],
                        model=models[name],
                    )
                )
        logger.info("llm_gateway_initialized", providers=[p.name for p in self.providers])

    @property
    def has_providers(self) -> bool:
        return bool(self.providers)

    # ---- redis safety ------------------------------------------------------

    def _redis_get(self, key: str) -> Any | None:
        """Redis read that degrades to None on outage (cache miss semantics)."""
        if not self.redis:
            return None
        try:
            return self.redis.get(key)
        except Exception as exc:  # noqa: BLE001 - cache must never break calls
            logger.warning("redis_unavailable_cache_disabled", error=str(exc)[:120])
            self.redis = None  # stop retrying for this gateway lifetime
            return None

    def _redis_write(self, fn: Any) -> None:
        if not self.redis:
            return
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("redis_write_failed", error=str(exc)[:120])
            self.redis = None

    # ---- budget / pacing -------------------------------------------------

    def _budget_allows(self, spec: ProviderSpec) -> bool:
        if not self.redis:
            return True
        today = datetime.now(UTC).strftime("%Y%m%d")
        key = f"llm:budget:{spec.name}:{today}"
        count = self._redis_get(key)
        return int(count or 0) < self.settings.llm_daily_budget

    def _record_budget_spend(self, spec: ProviderSpec) -> None:
        if not self.redis:
            return
        today = datetime.now(UTC).strftime("%Y%m%d")
        key = f"llm:budget:{spec.name}:{today}"

        def _spend() -> None:
            assert self.redis is not None  # guarded by _redis_write
            pipe = self.redis.pipeline()
            pipe.incr(key, 1)
            pipe.expire(key, 172_800)
            pipe.execute()

        self._redis_write(_spend)

    def _pace(self, spec: ProviderSpec) -> None:
        # Shared cooldown: after any 429 we hold ALL traffic for that provider
        # until the window clears, so consecutive cases never re-pay the penalty.
        cooldown_left = self._cooldown_until.get(spec.name, 0.0) - time.monotonic()
        if cooldown_left > 0:
            time.sleep(cooldown_left)

        if not self.redis or self.settings.llm_min_interval_ms <= 0:
            return
        key = f"llm:minint:{spec.name}"

        def _try_acquire() -> bool | None:
            if self.redis is None:
                return True  # pacing disabled: proceed unpaced
            try:
                return self.redis.set(key, "1", nx=True, px=self.settings.llm_min_interval_ms)
            except Exception as exc:  # noqa: BLE001 - pacing is best-effort
                logger.debug("pace_gate_unavailable", error=str(exc)[:120])
                return True

        acquired = _try_acquire()
        if acquired is False:
            time.sleep(self.settings.llm_min_interval_ms / 1000.0)

    def _engage_cooldown(self, spec: ProviderSpec, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        self._cooldown_until[spec.name] = max(self._cooldown_until.get(spec.name, 0.0), deadline)
        logger.warning("provider_cooldown_engaged", provider=spec.name, seconds=round(seconds, 1))

    # ---- public surface ---------------------------------------------------

    def chat_json(
        self, purpose: str, messages: list[dict[str, str]], bust_cache_key: str | None = None
    ) -> LlmResult:
        """Return a parsed JSON object from the first healthy provider.

        Raises NoProvidersConfigured / BudgetExhausted / AllProvidersFailed.
        `bust_cache_key` forces a network call even when a cached value exists
        (used by repair loops after semantic validation failures).
        """
        if not self.has_providers:
            raise NoProvidersConfigured("no LLM provider keys configured")

        chain_sig = ",".join(f"{p.name}:{p.model}" for p in self.providers)
        key = _cache_key(purpose, messages, chain_sig)
        if bust_cache_key and bust_cache_key == key:

            def _bust() -> None:
                assert self.redis is not None  # guarded by _redis_write
                self.redis.delete(key)

            self._redis_write(_bust)

        cached = self._redis_get(key)
        if cached:
            data = json.loads(cached)
            return LlmResult(
                payload=data["payload"],
                raw_content=data["raw_content"],
                provider=data["provider"],
                model=data["model"],
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=0,
                cache_hit=True,
                cache_key=key,
            )

        errors: list[str] = []
        for spec in self.providers:
            if not self._budget_allows(spec):
                errors.append(f"{spec.name}: daily budget exhausted")
                continue
            try:
                result = self._call_with_retries(spec, purpose, messages, key)
                self._record_budget_spend(spec)
                return result
            except (httpx.TimeoutException, httpx.HTTPStatusError, GatewayError) as exc:
                errors.append(f"{spec.name}: {type(exc).__name__}: {str(exc)[:160]}")
                logger.warning(
                    "provider_failed_falling_back", provider=spec.name, error=str(exc)[:200]
                )

        if all("daily budget exhausted" in e for e in errors):
            raise BudgetExhausted("; ".join(errors))
        raise AllProvidersFailed("; ".join(errors))

    # ---- internals --------------------------------------------------------

    def _call_with_retries(
        self, spec: ProviderSpec, purpose: str, messages: list[dict[str, str]], key: str
    ) -> LlmResult:
        attempts = 3
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                self._pace(spec)
                return self._call_once(spec, purpose, messages, key)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in _RETRY_STATUS:
                    raise
                last_error = exc
                if exc.response.status_code == 429:
                    wait_s = self._extract_429_wait(exc)
                    self._engage_cooldown(spec, min(wait_s, 90.0))
                    continue
            except httpx.TimeoutException as exc:
                last_error = exc
            backoff = 2.0 * (2 ** (attempt - 1)) * (1 + random.random() * 0.25)
            time.sleep(backoff)
        raise GatewayError(f"{spec.name}: exhausted {attempts} attempts: {last_error}")

    @staticmethod
    def _extract_429_wait(exc: httpx.HTTPStatusError) -> float:
        """Best-effort cooldown seconds from header or Groq's body hint."""
        header = exc.response.headers.get("retry-after")
        if header:
            try:
                return float(header)
            except ValueError:
                pass
        try:
            body = exc.response.json()
            message = str(body.get("error", {}).get("message", ""))
        except Exception:  # noqa: BLE001 - body may not be JSON
            message = ""
        # Groq phrasing: "...try again in 12.5s" / "in 850ms"
        import re as _re

        match = _re.search(r"try again in ([0-9.]+)\s*(ms|s)", message)
        if match:
            value = float(match.group(1))
            return value / 1000.0 if match.group(2) == "ms" else value
        return 20.0

    def _call_once(
        self, spec: ProviderSpec, purpose: str, messages: list[dict[str, str]], key: str
    ) -> LlmResult:
        started = time.monotonic()
        with httpx.Client(
            timeout=httpx.Timeout(
                connect=5.0,
                read=self.settings.llm_request_timeout_s,
                write=self.settings.llm_request_timeout_s,
                pool=5.0,
            )
        ) as client:
            response = client.post(
                f"{spec.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {spec.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": spec.model,
                    "messages": messages,
                    "temperature": 0.0,
                    "response_format": {"type": "json_object"},
                    "max_tokens": 700,
                },
            )
            response.raise_for_status()
            latency_ms = int((time.monotonic() - started) * 1000)
            body = response.json()

        content = body["choices"][0]["message"]["content"]
        usage = body.get("usage", {})
        try:
            payload = json.loads(content)
            if not isinstance(payload, dict):
                raise ValueError("top-level JSON is not an object")
        except (json.JSONDecodeError, ValueError) as exc:
            raise GatewayError(f"{spec.name}: non-JSON content: {exc}") from exc

        result = LlmResult(
            payload=payload,
            raw_content=content,
            provider=spec.name,
            model=spec.model,
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=latency_ms,
            cache_hit=False,
            cache_key=key,
        )

        def _cache_write() -> None:
            assert self.redis is not None
            self.redis.setex(
                key,
                86_400,
                json.dumps(
                    {
                        "payload": result.payload,
                        "raw_content": result.raw_content,
                        "provider": result.provider,
                        "model": result.model,
                    }
                ),
            )

        self._redis_write(_cache_write)
        return result
