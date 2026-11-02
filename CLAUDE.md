# Ontolite
Governed data layer + MCP server. Python 3.11+, MIT.
## Commands
- Setup: `pip install -e .[dev]`; Test: `pytest -q`; Lint/types: `ruff check . && pyright`
## Rules
- Zero spend. Secrets only from env (`.env` is git-ignored). No live model calls in tests.
- Reads fail closed. Denials must be indistinguishable from absence. Never add a code path that touches data before the allowed set is computed.
- Heuristics are labelled; never write "secure"/"guaranteed". README claims link to a test.
