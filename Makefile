.PHONY: help dev install test lint clean

PYTHON ?= python3.11
VENV := .venv
ACTIVATE := . $(VENV)/bin/activate

help:
	@echo "ThreatSimGPT Developer Commands"
	@echo ""
	@echo "make dev       → Create venv and install dev dependencies"
	@echo "make install   → Install project in editable mode"
	@echo "make test      → Run test suite"
	@echo "make lint      → Run formatting checks"
	@echo "make clean     → Remove virtual environment"

dev:
	$(PYTHON) -m venv $(VENV)
	$(ACTIVATE) && pip install --upgrade pip
	$(ACTIVATE) && pip install -e .
	$(ACTIVATE) && pip install -r requirements-dev.txt

install:
	$(ACTIVATE) && pip install -e .

test:
	$(ACTIVATE) && pytest

lint:
	$(ACTIVATE) && black .

clean:
	rm -rf $(VENV)
