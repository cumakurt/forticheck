# FortiCheck — Makefile for install, test, lint, and Docker
# Usage: make [target]; make help

PYTHON ?= python3
PIP ?= pip
IMAGE_NAME ?= forticheck:latest
WORKSPACE ?= /workspace

.PHONY: help install install-dev test lint typecheck clean docker-build docker-run docker-diff

help:
	@echo "FortiCheck — available targets:"
	@echo "  make install       Install dependencies and package (editable)."
	@echo "  make install-dev   Install with dev dependencies (pytest, ruff, mypy)."
	@echo "  make test          Run tests with pytest."
	@echo "  make lint          Run ruff linter."
	@echo "  make typecheck     Run mypy type checker."
	@echo "  make clean         Remove build artifacts and caches."
	@echo "  make docker-build  Build Docker image ($(IMAGE_NAME))."
	@echo "  make docker-run CONFIG=<file.conf>  Run analysis in Docker; report in current directory."
	@echo "  make docker-diff BEFORE=<old.conf> AFTER=<new.conf>  Run config diff in Docker."

install:
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

install-dev:
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

lint:
	$(PYTHON) -m ruff check forticheck/ tests/

typecheck:
	$(PYTHON) -m mypy forticheck/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .eggs/
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf .mypy_cache/

docker-build:
	docker build -t $(IMAGE_NAME) .

docker-run:
	@if [ -z "$(CONFIG)" ]; then echo "Usage: make docker-run CONFIG=your.conf"; exit 1; fi
	docker run --rm -v "$$(pwd):$(WORKSPACE)" $(IMAGE_NAME) analyze -c $(WORKSPACE)/$(CONFIG)

docker-diff:
	@if [ -z "$(BEFORE)" ] || [ -z "$(AFTER)" ]; then echo "Usage: make docker-diff BEFORE=old.conf AFTER=new.conf"; exit 1; fi
	docker run --rm -v "$$(pwd):$(WORKSPACE)" $(IMAGE_NAME) diff --before $(WORKSPACE)/$(BEFORE) --after $(WORKSPACE)/$(AFTER) -o $(WORKSPACE)/diff_result.json
