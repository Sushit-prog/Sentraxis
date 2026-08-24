# Cyber Resilience Platform

Agentic detection-and-response platform for critical infrastructure — built from
[ET AI Hackathon 2026, Problem Statement #7: "AI-Driven Cyber Resilience for
Critical National Infrastructure"](docs/decisions/).

Behavioral anomaly detection → incident correlation (MITRE ATT&CK-mapped) →
policy-gated response orchestration with human-in-the-loop approvals → immutable
audit trail. The deterministic spine functions with zero LLM calls; LLMs enrich
correlation behind enforced output contracts.

> **Status:** Milestone M0 (repository foundation). See
> [Milestone roadmap](#milestone-roadmap).

## Stack

| Layer      | Choice                                   |
| ---------- | ---------------------------------------- |
| Language   | Python 3.12 (uv, lockfile)               |
| API        | FastAPI + Uvicorn                        |
| Datastore  | PostgreSQL 16 (SQLAlchemy 2.0 sync)      |
| Streaming  | Redis Streams (consumer groups)          |
| Migrations | Alembic                                  |
| Logging    | structlog (JSON, redaction processor)    |
| CI         | GitHub Actions (lint, typecheck, tests)  |

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker Desktop / Engine with Compose v2

## Quickstart

```bash
cp .env.example .env     # adjust if needed; defaults target docker-compose
uv sync                  # creates .venv from uv.lock
docker compose up -d --build
make migrate             # apply alembic migrations

curl http://localhost:8000/healthz   # -> {"status":"ok"}
curl http://localhost:8000/readyz    # -> {"status":"ready","checks":{...}}
```

Interactive API docs: <http://localhost:8000/docs>

## Development

```bash
make install             # uv sync
make check               # lint + format-check + typecheck + all tests
make test                # unit tests only (no services needed)
make up-deps             # postgres + redis only, for integration tests
make test-integration    # requires up-deps
```

Configuration is environment-driven (`.env` / process env); missing required
variables fail fast at startup. See `.env.example`.

## Project layout

```text
src/app/
├── api/            # HTTP layer (health today; incidents/actions later)
├── domain/         # canonical event contracts (strict validation)
├── persistence/    # engine, ORM models, idempotent repositories
├── workers/        # normalizer (streams→DB) and replay injector CLIs
├── observability/  # structured logging config, redaction
├── config.py       # pydantic-settings, fail-fast validation
└── main.py         # app factory
migrations/         # alembic revisions
tests/
├── unit/           # business logic, no live services
└── integration/    # requires docker compose deps
scenarios/          # labeled attack replays (JSONL)
docs/decisions/     # architecture decision records
```

## Milestone roadmap

| M | Scope                                                          | Status |
| - | -------------------------------------------------------------- | ------ |
| 0 | Repo foundation: tooling, config, compose, health, CI          | ✅     |
| 1 | Ingestion + normalization + event store + replay injector      | ✅ (1.6k ev/s bench) |
| 2 | Behavioral baselines + anomaly detectors + detection eval      | 🚧 slice 1 ([ADR-004](docs/decisions/ADR-004-detection-engine.md), [ADR-005](docs/decisions/ADR-005-db-cursor-detection.md)) |
| 3 | Incidents (rule correlation) + API + JWT/RBAC                  | ⬜     |
| 4 | LLM gateway + correlation agent + failure/security tests       | ⬜     |
| 5 | Response orchestrator + playbooks + approvals + audit chain    | ⬜     |
| 6 | Observability + load testing + security review                 | ⬜     |
| 7 | Golden-set evaluation suite + published metrics                | ⬜     |
| 8 | prod-lite deployment + demo scenario + documentation polish    | ⬜     |

## Limitations (honest, current)

- No authentication yet (arrives with the first protected API surface in M3).
- Demo/dev credentials are intentionally static in `docker-compose.yml`; production
  profile will inject secrets via environment.
- Integration tests require local Docker.
