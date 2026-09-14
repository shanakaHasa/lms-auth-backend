.PHONY: help venv lock api migrate revision downgrade seed drift test test-unit test-int lint fmt typecheck check db-check clean

# Cross-platform: GNU Make sets OS=Windows_NT on Windows. Without this, every
# target is unusable on Linux -- which is where CI runs.
ifeq ($(OS),Windows_NT)
	PY := .venv/Scripts/python.exe
else
	PY := .venv/bin/python
endif

lock:      ## Freeze the resolved tree so builds are reproducible
	$(PY) -m pip freeze --exclude-editable > requirements.lock

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

venv:      ## Create the venv and install the project with dev extras
	python -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

api:       ## Run the API with reload on :8001
	$(PY) -m uvicorn app.main:app --reload --port 8001

# ── Database ────────────────────────────────────────────────────────────────
# There is no local Postgres. DATABASE_URL points at the Aurora cluster that
# ../platform provisions. If a connection hangs for ~15s the cluster was paused
# and is resuming -- that is the cost of min_capacity = 0.

db-check:  ## Verify the database is reachable, and report version and latency
	$(PY) -m app.cli db-check

migrate:   ## Apply migrations
	$(PY) -m alembic upgrade head
revision:  ## Autogenerate a migration: make revision m="add x"
	$(PY) -m alembic revision --autogenerate -m "$(m)"
downgrade: ## Roll back one migration
	$(PY) -m alembic downgrade -1

seed:      ## Seed a local institution with users
	$(PY) -m app.cli seed-dev

# ── Quality ─────────────────────────────────────────────────────────────────

test:      ## Unit suite (integration is excluded by default; see test-int)
	$(PY) -m pytest
test-unit: ## Unit only -- no database, runs anywhere, fast
	$(PY) -m pytest tests/unit
test-int:  ## Integration -- needs a real Postgres with migrations applied
	$(PY) -m pytest tests/integration -m integration

lint:      ## Lint
	$(PY) -m ruff check .
typecheck: ## Type check
	$(PY) -m mypy app
fmt:       ## Format and autofix
	$(PY) -m ruff format .
	$(PY) -m ruff check --fix .
drift:     ## Diff model DDL against migration DDL -- needs no database
	$(PY) scripts/check_migration_drift.py
check: lint typecheck drift test-unit  ## What CI runs before the integration stage

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
