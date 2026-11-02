# ontolite

A small, readable governed-data layer: agents read **typed objects** and change them only through **staged, approved, logged actions**, and every answer is filtered by **who is asking**. Inspired by public ontology concepts; no claim of compatibility with any vendor product.

```bash
pip install -e .[dev]            # 1. install
ontolite init && ontolite ingest # 2. demo project in .ontolite/ with the (synthetic, SEC-layout) sample data
ontolite serve --principal alice # 3. MCP server over stdio, acting as analyst "alice"
```
Real SEC data: the `demo-data` workflow downloads the Financial Statement Data Sets (see `.github/workflows/demo-data.yml`); `ontolite ingest --data DIR` loads them.

## How it works
```
agent --MCP--> mcp_server (one principal per server) --> Retriever: principal -> allowed set -> data -> visible props
                                                     \-> ActionEngine: propose -> (approve) -> apply (atomic) -> provenance
every decision -> hash-chained audit log      schema proposals from a model -> human approval gate
```
Agents act *for* a user and never exceed that user. Same question, different principals, different correct answers (see `tests/test_mcp_cli.py`).

## Verified claims
| Claim | Evidence |
| --- | --- |
| 0 restricted values leaked across 200+ adversarial retrievals (search, filters, get, traversal, aggregates, prompt-style strings) with a non-vacuous control | [tests/test_leakage.py](tests/test_leakage.py) |
| Editing, deleting or reordering any audit entry fails `audit verify` | [tests/test_audit.py](tests/test_audit.py) |
| Out-of-edit-set actions rejected; handles principal-bound, single-use, expiring, unguessable; atomic apply | [tests/test_actions.py](tests/test_actions.py) |
| Schema proposals never apply without approval, incl. hostile model output | [tests/test_propose.py](tests/test_propose.py) |
| Reads fail closed (store down, truncated allow-list) | [tests/test_permissions.py](tests/test_permissions.py) |
| Unrelated grants never widen access (property test) | `test_unrelated_grants_never_widen_access` |
| End-to-end over MCP with a current-revision and an earlier-revision client | [tests/test_mcp_cli.py](tests/test_mcp_cli.py) |

## Limitations (plain words)
See [docs/threat-model.md](docs/threat-model.md): tail truncation is undetectable without a pinned head; the audit file is unsigned; the MCP server trusts its configured principal (no network authN); SQLite single-process.
The sample data is **synthetic**; the real-data workflow is unverified from the build sandbox (sec.gov not reachable). The 200-probe suite is evidence, not proof. DuckDB-vs-SQLite spike not run ([ADR-001](docs/adr/001-sqlite.md)). Ontolite-Bench (40 live-model tasks) is not included; it needs model keys and free-tier runs.

## What I would do differently
Run the store spike, add OpenFGA adapter, and sign audit entries (Ed25519) with an external head anchor.

## Configuration
Copy `.env.example` to `.env` (git-ignored). No keys needed to run or test.

## AI assistance
Written with Claude Code; reviewed claims are backed by tests above. MIT licensed. See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [CHANGELOG](CHANGELOG.md).
