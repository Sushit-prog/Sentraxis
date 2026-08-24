.PHONY: install lint fmt fmt-check typecheck test test-integration test-all up up-deps down logs migrate check clean

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
	uv run mypy src

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

clean:
	docker compose down -v
