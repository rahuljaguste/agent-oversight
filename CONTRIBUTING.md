# Contributing

This is a prototype. Issues and pull requests are welcome.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pytest
ruff check .
ruff format --check .
python evals/run.py
python benchmarks/latency.py
```

The tests, evals and benchmark run offline. Only the interactive demo needs a model; see the README.

## Guidelines

- Mock tools only. Do not add real money movement, email delivery, network fetch or secrets.
- Add or update an eval scenario when you change the policy.
- Keep the dependency surface small.
- Do not commit `.env` files, API keys or runtime output.

For security reports, see [`SECURITY.md`](SECURITY.md).
