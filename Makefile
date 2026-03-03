.PHONY: help install dev run test lint migrate init-db docker-up docker-down docker-build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install project dependencies
	pip install -e ".[all]"

dev: ## Run Flask development server locally
	FLASK_APP=dimsum.app:create_app FLASK_ENV=development flask run --reload

test: ## Run tests with pytest
	pytest tests/ -v --tb=short

lint: ## Run ruff linter
	ruff check src/ tests/

lint-fix: ## Run ruff linter with auto-fix
	ruff check --fix src/ tests/

init-db: ## Initialize the database and run migrations
	FLASK_APP=dimsum.app:create_app flask db upgrade

migrate: ## Create a new migration
	FLASK_APP=dimsum.app:create_app flask db migrate -m "$(msg)"

docker-build: ## Build Docker images
	docker compose build

docker-up: ## Start all services with Docker Compose
	docker compose up -d

docker-down: ## Stop all services
	docker compose down

docker-logs: ## View logs from all services
	docker compose logs -f

docker-shell: ## Open a shell in the web container
	docker compose exec web bash

celery-worker: ## Run Celery worker locally
	celery -A dimsum.celery_app:celery worker --loglevel=info -Q scans,reports,analysis
