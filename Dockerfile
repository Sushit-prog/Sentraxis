# ---- Build stage: install dependencies with uv into a self-contained venv ----
# NOTE: builder and runtime must share the same WORKDIR path so that the venv's
# absolute console-script shebangs (e.g. /opt/app/.venv/bin/python) remain valid.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /opt/app

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --no-editable

COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ---- Runtime stage: minimal image, non-root user ----
FROM python:3.12-slim AS runtime

RUN groupadd -r app && useradd -r -g app --home-dir /opt/app app

WORKDIR /opt/app
COPY --from=builder --chown=app:app /opt/app/.venv ./.venv

ENV PATH="/opt/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

USER app
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
