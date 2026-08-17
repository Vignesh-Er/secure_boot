.PHONY: help setup keys sign boot collect train eval attack demo demo-safe test lint coverage clean

PYTHON ?= python

help:
	@echo "BootSentry Build & Automation Targets:"
	@echo "  make setup       Install dependencies"
	@echo "  make keys        Generate PQC ML-DSA-65 keys"
	@echo "  make sign        Sign all stage manifests"
	@echo "  make boot        Execute single clean boot flow"
	@echo "  make collect     Collect real process boot telemetry"
	@echo "  make train       Train anomaly detection models"
	@echo "  make eval        Run evaluation & generate report.html"
	@echo "  make attack      Execute attack scenario testbed"
	@echo "  make demo        Run live Rich TUI boot demo"
	@echo "  make demo-safe   Run replay mode for safe demo"
	@echo "  make test        Run full pytest suite"
	@echo "  make lint        Run ruff linter"
	@echo "  make coverage    Run pytest coverage report"
	@echo "  make clean       Clean cache and temporary files"

setup:
	$(PYTHON) -m pip install -r requirements.txt

keys:
	$(PYTHON) -m bootsentry.crypto.keys --out-dir config/keys

sign:
	$(PYTHON) -m bootsentry.crypto.sign --keys-dir config/keys --stages-dir config/stages

boot:
	$(PYTHON) -m bootsentry.boot.runner --config config/policy.yaml

collect:
	$(PYTHON) -m bootsentry.eval.collector --count $(or $(N), 500) --out-dir data/telemetry

train:
	$(PYTHON) -m bootsentry.eval.trainer --data-dir data/telemetry --models-dir models

eval:
	$(PYTHON) -m bootsentry.eval.evaluate --models-dir models --out-dir eval

attack:
	$(PYTHON) -m bootsentry.attacks.runner --all

demo:
	$(PYTHON) -m bootsentry.demo.tui --interactive

demo-safe:
	$(PYTHON) -m bootsentry.demo.tui --safe-replay

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	$(PYTHON) -m ruff check src/ tests/

coverage:
	$(PYTHON) -m pytest --cov=src/bootsentry --cov-report=term-missing tests/

clean:
	$(PYTHON) -c "import shutil, glob, os; [shutil.rmtree(p, ignore_errors=True) for p in glob.glob('**/__pycache__', recursive=True) + glob.glob('.pytest_cache') + glob.glob('.coverage') + glob.glob('*.egg-info')]"
