# Changelog
## 0.2.0
- **Authorisation engine**: Zanzibar-style relation rewrites (this/computed/ttu/union/intersection/exclusion), versioned tuples with snapshot reads, link-backed tuplesets, cycle and depth handling that denies; differential-tested against an independent oracle and a stateful test.
- **Store**: SQL pushdown of (allowed set, visible properties) so hidden data never leaves the engine; `Reach` compiles hierarchical permissions into joins; DuckDB backend; the store spike was actually run (ADR-001).
- **Queries**: typed `QueryType`s with small-cell suppression. **Migrations**: validated, transactional, destructive steps need consent.
- **Audit**: RFC 6962 Merkle tree, inclusion/consistency proofs, Ed25519 signed heads, truncation detection against pinned heads.
- **HTTP MCP** with hashed, expiring, revocable bearer tokens; one server, many principals.
- **Ontolite-Bench**: 40 Inspect tasks, reference solutions, state graders, null/adversary controls and per-control mutation testing.
- Fuzzer (found an unhandled-exception defect, fixed); SQLite boolean-filter bug found by tests and fixed.
## 0.1.0
First version (toy relationship matcher, SQLite only).
