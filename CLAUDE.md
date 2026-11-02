# Ontolite
Governed data layer + MCP server. Python 3.11+, MIT.
## Commands
- Setup: `pip install -e .[dev]`; Test: `pytest -q`; Lint/types: `ruff check . && pyright`
- Bench (no model): `python bench/report.py` regenerates docs/bench.md; store spike: `python bench/store_spike.py`
## Rules
- Zero spend. Secrets only from env (`.env` is git-ignored). No live model calls in tests.
- Reads fail closed: ANY backend exception becomes a denial. Denials must be indistinguishable from absence. Never touch data before the allowed set is known. Hidden properties must never be extracted by SQL.
- A new control needs a test AND, if it guards something in the bench, a mutant proving the graders see its absence.
- Never write "secure"/"guaranteed". README claims link to a test or a generated file.
