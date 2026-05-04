.PHONY: help setup lint fmt type security test test-unit test-int run clean

help:
	@echo "Targets:"
	@echo "  setup     - install dev dependencies (uv pip install -e .[dev])"
	@echo "  lint      - ruff check ."
	@echo "  fmt       - ruff format ."
	@echo "  type      - mypy app/ (strict)"
	@echo "  security  - bandit -r app/"
	@echo "  test      - pytest"
	@echo "  test-unit - pytest tests/unit"
	@echo "  test-int  - pytest tests/integration"
	@echo "  run       - uvicorn dev server on 127.0.0.1:8000"
	@echo "  clean     - remove caches"

setup:
	uv pip install -e ".[dev]"
	-pre-commit install

lint:
	ruff check .

fmt:
	ruff format .

type:
	mypy app/

security:
	bandit -r app/ -c pyproject.toml

test:
	pytest

test-unit:
	pytest tests/unit

test-int:
	pytest tests/integration

run:
	uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
