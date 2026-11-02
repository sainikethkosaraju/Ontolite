<h1 align="center">Ontolite</h1>

<p align="center"><b>A governed data layer for AI agents, served over MCP.</b><br>Typed objects, staged and approved actions, and answers filtered by <i>who is asking</i>, enforced inside the query.</p>

<p align="center">
  <a href="https://github.com/sainikethkosaraju/ontolite/actions/workflows/ci.yml"><img src="https://github.com/sainikethkosaraju/ontolite/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license">
</p>

<p align="center"><a href="#quickstart">Quickstart</a> · <a href="#what-is-in-it">What is in it</a> · <a href="#evidence">Evidence</a> · <a href="#limitations">Limitations</a> · <a href="docs/threat-model.md">Threat model</a> · <a href="docs/adr/001-store.md">ADR-001</a></p>

---
A governed data layer for AI agents. Agents read **typed objects** and change them only through **staged, approved, audited actions**, and every answer is filtered by **who is asking**, enforced inside the query rather than after it. Exposed as an MCP server (stdio, or HTTP with per-principal bearer tokens). Inspired by publicly documented ontology and Zanzibar-style authorization ideas; **no claim of compatibility with, or endorsement by, any vendor.**

## Quickstart

```bash
pip install -e ".[dev]"
ontolite init && ontolite ingest                 # demo project (synthetic data in the SEC Financial Statement layout)
ontolite serve --principal alice                 # MCP over stdio as analyst "alice"  (or: --transport http, see below)
```

## What is in it
- **Authorization engine** ([`authz/`](src/ontolite/authz)): relation rewrites (`this`, `computed`, `ttu`, union, intersection, **exclusion**), versioned tuples with snapshot reads, tuplesets derived from the *data graph* (a fact is visible if its filing is, a filing if its company is), compliance walls as exclusions, cycle handling where **any evaluation error denies**.
- **Enforcement in the query** ([`store/`](src/ontolite/store)): the allowed set and visible-property list are compiled into SQL. Restricted properties are never extracted from storage and hidden rows are never selected. Hierarchical permissions compile to a link-reach join instead of a million-key list. SQLite by default, DuckDB optional.
- **Typed queries** with small-cell suppression; **governed actions** (propose, approve by a different principal, apply atomically with provenance); **schema proposals + migrations** behind a human gate (destructive steps need explicit consent, all-or-nothing).
- **Audit**: hash chain plus an RFC 6962 Merkle tree with inclusion/consistency proofs and Ed25519-signed heads, so truncation or a recomputed rewrite is detectable against a head pinned off-box.
- **Ontolite-Bench**: 40 Inspect AI tasks with reference solutions and state graders, plus mutation testing of the governance layer itself.

## How it works
```
agent --MCP--> mcp_server (principal from bearer token) --> Retriever: principal -> allowed set (Reach | keys) -> SQL(visible cols only)
                                                       \-> ActionEngine: propose -> approve(other principal) -> apply(tx) -> provenance
every decision --> hash-chained, Merkle-indexed audit log        model-proposed schema --> digest-bound human approval --> migration
```
Request walk-through: [docs/walkthrough-M2.md](docs/walkthrough-M2.md). Concepts: [docs/concepts.md](docs/concepts.md).

## Evidence
| Claim | Evidence |
| --- | --- |
| 0 restricted values returned across 200+ adversarial probes x 3 principals x **both backends** | [tests/test_leakage.py](tests/test_leakage.py) (includes a non-vacuous control) |
| Random principals x operations x hostile arguments never leak; audit and provenance stay consistent | [tests/test_fuzz.py](tests/test_fuzz.py) (it found a real crash on bad filter values; fixed) |
| Relation engine equals an independent bottom-up oracle on 250 random schemas, and under interleaved writes (stateful) | [tests/test_authz.py](tests/test_authz.py) |
| Compiled `Reach` results equal the generic engine for every principal | [tests/test_pushdown_queries_migrate.py](tests/test_pushdown_queries_migrate.py) |
| Merkle roots match the RFC 6962 reference vectors; inclusion/consistency proofs hold for all sizes and reject tampering | [tests/test_merkle.py](tests/test_merkle.py) |
| Truncation of the audit tail is detected against a pinned signed head even when the local chain still verifies | `tests/test_merkle.py`, `tests/test_mcp_cli.py` |
| One HTTP server serves many principals; forged/expired tokens get 401 | [tests/test_http_auth.py](tests/test_http_auth.py) |
| Reads fail closed (backend down, truncated allow-list, cycle under exclusion) | [tests/test_permissions.py](tests/test_permissions.py) |
| Benchmark graders can fail: reference 40/40, do-nothing agent 6/40, every deliberately broken control is detected | [docs/bench.md](docs/bench.md), [tests/test_bench.py](tests/test_bench.py) |
| Coverage 94% overall; permission/authz/audit/action/store modules each >= 91% | `pytest --cov` (CI) |

### Store decision (measured, not assumed) - [ADR-001](docs/adr/001-store.md)
300k facts / 20k filings, 4 vCPU sandbox: compiled `Reach` is **3.6x (SQLite) / 4.8x (DuckDB)** faster than a materialised key list on permissioned aggregates (184 ms vs 662 ms; 60 ms vs 291 ms). DuckDB wins wide scans (50 ms vs 431 ms) but loses point reads (2.8 s vs 7 ms per 1,000), so SQLite is the default. An early DuckDB result (198 s load) was a measurement artefact of row-wise inserts and is explained in the ADR.

## HTTP transport
```bash
ontolite token issue alice            # prints the bearer token once; only its SHA-256 is stored
ontolite serve --transport http --port 8000
```
### Live run on real SEC data
`demo-data` ran on a real SEC Financial Statement quarter ([run log](https://github.com/sainikethkosaraju/ontolite/actions/runs/41409618248)): 6,516 filings, 140,198 facts. Same question, different principals: alice sees 2 companies / 454 facts (no `risk_rating`), walter 1 / 259, rita 5 / 956 (with `risk_rating`); the audit chain verified.

## Limitations
Read [docs/threat-model.md](docs/threat-model.md). Highlights: the audit log is only tamper-*evident* against a head you pinned elsewhere; the process owner can read the database; stdio trusts its `--principal`; the HTTP auth is a token issuer, not OIDC; single-process; a remote authorization engine adapter (OpenFGA) is defined but **not implemented**.
**Data:** the committed sample is *synthetic* in the SEC layout. `sec.gov` was not reachable from the build sandbox, so the real-data workflow (`.github/workflows/demo-data.yml`) is **unverified**.
**Benchmark:** the 40 tasks are validated with deterministic solvers only. **No real-model results are reported**; that needs your model keys (`inspect eval bench/ontolite_bench/inspect_tasks.py -T solver=agent`). The tool-integrity gate in the bench is a local stand-in; Toolpin's repo repeats that ablation with the real gate.

## What I would do differently
Run the real-model benchmark early (cassettes via Passk) and implement the OpenFGA adapter to show the provider seam is real, not only defined.

## Configuration
Copy `.env.example` to `.env` (git-ignored). No API keys are needed to run or test.

## AI assistance
Written with Claude Code; every claim above links to a test or a generated artefact. MIT licensed. See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [CHANGELOG](CHANGELOG.md).

## The stack
Three independent, MIT-licensed repositories that answer one question: *how do you let an agent touch real data and take real actions, and prove it behaves?*

| Repo | Role |
| --- | --- |
| [**ontolite**](https://github.com/sainikethkosaraju/ontolite) | the governed data layer: typed objects, staged actions, per-principal answers, tamper-evident audit |
| [**toolpin**](https://github.com/sainikethkosaraju/toolpin) | the trust layer between agent and tools: pinned definitions, information-flow control, approvals bound to the exact call |
| [**passk**](https://github.com/sainikethkosaraju/passk) | the measurement layer: reliability (pass^k) with honest intervals, cost per success, regression gates |
