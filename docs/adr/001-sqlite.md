# ADR-001: SQLite as the embedded store
Decision: SQLite (stdlib). Reasons: zero dependencies, runs in CI, transactional (`BEGIN IMMEDIATE`)
for atomic apply. The blueprint's DuckDB-vs-SQLite one-hour spike was **not run**; no timing claims are
made. Revisit if analytic scans over the full SEC dataset prove slow. The store interface is small (`put/get/keys/link/neighbours/transaction`).
