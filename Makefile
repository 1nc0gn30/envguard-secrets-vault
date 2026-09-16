.PHONY: help test test-cov lint format serve mcp clean install

PYTHON ?= python3
PORT ?= 8087
HOST ?= 0.0.0.0

help:
	@echo "EnvGuard Secrets Vault - Available Commands:"
	@echo "  make install    Install package locally in editable mode"
	@echo "  make test       Run full test suite using pytest"
	@echo "  make test-cov   Run tests with coverage reporting"
	@echo "  make test-cli   Run internal CLI engine verification test"
	@echo "  make serve      Start Google Material 3 Secrets Studio Web UI"
	@echo "  make mcp        Run stdio Model Context Protocol (MCP) server"
	@echo "  make clean      Remove build artifacts and cache directories"

install:
	$(PYTHON) -m pip install -e .

test:
	PYTHONPATH=src $(PYTHON) -m pytest tests -v

test-cov:
	PYTHONPATH=src $(PYTHON) -m pytest tests --cov=envguard_secrets_vault --cov-report=term-missing -v

test-cli:
	PYTHONPATH=src $(PYTHON) -m envguard_secrets_vault test

serve:
	PYTHONPATH=src $(PYTHON) -m envguard_secrets_vault serve --port $(PORT) --host $(HOST)

mcp:
	PYTHONPATH=src $(PYTHON) -m envguard_secrets_vault mcp

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov __pycache__ src/envguard_secrets_vault/__pycache__ tests/__pycache__
