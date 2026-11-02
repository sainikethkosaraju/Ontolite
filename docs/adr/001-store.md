# ADR-001: SQLite by default, DuckDB optional, permissions compiled into the query

**Status:** accepted. **Evidence:** [`bench/store_spike.py`](../../bench/store_spike.py) (raw output: [001-store-results.json](001-store-results.json)); medians of 3-5 runs, 4 vCPU x86_64 sandbox, Python 3.13, SQLite 3.53.1, DuckDB 2.0.0. Data is synthetic and SEC-shaped (2,000 companies, 20,000 filings, 300,000 facts, 320,000 links). Treat the ratios as indicative, not universal.

| measurement | SQLite | DuckDB |
| --- | --- | --- |
| bulk load, 320k rows (set-based path) | 1.1 s | 5.2 s |
| 1,000 point gets | 7 ms | 2,781 ms |
| 1,000 link traversals | 7 ms | 4,027 ms |
| unrestricted aggregate (sum by tag) | 431 ms | 50 ms |
| permissioned aggregate, allowed set as 90k-key list | 662 ms | 291 ms |
| permissioned aggregate, allowed set as compiled `Reach` (600 roots) | **184 ms** | **60 ms** |
| permissioned text search, key list / `Reach` | 468 / 203 ms | 386 / 161 ms |

## Findings that changed the design
1. **Materialising the allowed set is the bottleneck.** Staging 90k fact keys cost more than the query. Permissions are therefore compiled: when an object type inherits visibility along data links (`viewer: ttu(link, viewer)`), only the *roots* (600 allowed companies) are staged and the hops become nested `IN` subqueries. Result: 3.6x (SQLite) and 4.8x (DuckDB) faster than the key list, with identical results (`reach_equals_keyset` is checked in the benchmark and in `tests/test_pushdown.py`).
2. **My first DuckDB path was a measurement artefact.** Row-by-row `executemany` took 198 s to load and 51 s to stage a key list. Set-based `unnest` inserts fixed both (5.2 s, 0.14 s for 100k keys). The OLTP numbers (per-statement overhead, ~2.8 ms per point get) are inherent.
3. **Workload decides the engine.** Staged actions need fast point reads/writes and transactions -> SQLite. Wide analytic aggregates over facts -> DuckDB is 3-9x faster. Both implement the same `SQLStore` pushdown API, run the same leakage suite, and the choice is a config switch (`--backend duckdb`).

## Not measured
Concurrency, on-disk datasets larger than RAM, indexes on JSON properties, and cold-cache behaviour.
