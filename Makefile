.PHONY: install lint fmt fmt-check typecheck test test-integration test-all up up-deps down logs migrate check clean gen-bulk bench eval-detect eval-correlate check-llm audit-verify

install:
	uv sync

lint:
	uv run ruff check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

fmt-check:
	uv run ruff format --check .

typecheck:
	uv run mypy src scripts

test:
	uv run pytest -m "not integration"

test-integration:
	uv run pytest -m integration

test-all:
	uv run pytest

up:
	docker compose up -d --build

# Only infrastructure services, for running integration tests locally
up-deps:
	docker compose up -d postgres redis

down:
	docker compose down

logs:
	docker compose logs -f api

migrate:
	uv run alembic upgrade head

check: lint fmt-check typecheck test-all

# 50k-event synthetic scenario for throughput benchmarking
gen-bulk:
	uv run python scripts/generate_bulk_scenario.py --events 50000 --attack-ratio 0.1

bench:
	uv run python scripts/bench_replay.py --scenario scenarios/bulk_bench.jsonl

# Offline detection evaluation (requires full stack + detector worker running)
eval-detect:
	uv run python scripts/run_eval_detection.py --scenario scenarios/port_scan_probe.jsonl

eval-correlate:
	uv run python scripts/run_eval_correlation.py --require-keys

check-llm:
	@uv run python -c "from app.config import get_settings; from app.llm.gateway import LlmGateway; g=LlmGateway(get_settings()); print('providers:', [p.name for p in g.providers] or 'NONE - rule-only mode')"

audit-verify:
	uv run python scripts/verify_audit_chain.py

clean:
	docker compose down -v
