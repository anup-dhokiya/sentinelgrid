.PHONY: help dev down logs test test-unit test-sec lint migrate seed clean

help:
	@echo "SentinelGrid Build & Test Automation"
	@echo "------------------------------------"
	@echo "make dev         Start local stack via Docker Compose"
	@echo "make down        Stop all Docker Compose services"
	@echo "make logs        Tail all service logs"
	@echo "make test        Run all unit and integration test suites"
	@echo "make test-unit   Run backend and connector unit tests"
	@echo "make test-sec    Run security test fixtures (SQLi, XSS, Traversal)"
	@echo "make lint        Run flake8, black, and mypy checks"
	@echo "make migrate     Apply Alembic database migrations"
	@echo "make seed        Seed initial development tenant, user, and rules"
	@echo "make clean       Remove temporary build and cache artifacts"

dev:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

test: test-unit test-sec

test-unit:
	pytest backend/tests/unit -v

test-sec:
	pytest security-tests/waf -v

lint:
	black --check backend connectors
	flake8 backend connectors
	mypy backend/app

migrate:
	alembic -c backend/alembic.ini upgrade head

seed:
	python3 -m backend.scripts.seed_dev_data

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache
