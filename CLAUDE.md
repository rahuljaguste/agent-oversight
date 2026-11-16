# Agent Oversight

Read `HANDOFF.md` first. It is the local-only task brief and the source of truth for the next steps; it is not published with the repository.

## Project rules

- This is a prototype, not production software.
- Use mock tools only. No real money movement, email delivery, network fetch or secrets.
- Run `pytest`, `ruff check .`, `ruff format --check .` and `python evals/run.py` before finishing.
- Do not invent results. Every metric in the README must be measured by the eval runner or a reproducible benchmark.
- Keep the dependency surface small and the code readable.
- Keep the public README and DESIGN focused on the project, not on the author.
