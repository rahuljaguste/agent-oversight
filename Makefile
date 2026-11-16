.PHONY: install test lint evals bench demo

install:
	python -m pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .
	ruff format --check .

evals:
	python evals/run.py

bench:
	python benchmarks/latency.py

demo:
	python -m agent_oversight demo
