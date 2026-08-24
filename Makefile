.PHONY: install lint fmt fmt-check typecheck test test-integration test-all up up-deps down logs migrate check clean gen-bulk bench

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

clean:
	docker compose down -v
