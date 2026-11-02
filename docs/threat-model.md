# Threat model
**Assets:** restricted properties and objects; the integrity of the store; the integrity and completeness of the audit trail.
**Adversaries:** an over-curious or prompt-injected agent; a user probing beyond their grants; a client forging or replaying handles and tokens; an operator who can edit files on disk.

| Threat | Control | Evidence |
| --- | --- | --- |
| Reading a restricted property/object (get, search, filters, traversal, aggregates, queries) | allowed set computed first, compiled into the SQL (`Reach`/key set); hidden properties never extracted; search text matches visible properties only; denial == absence | `tests/test_leakage.py` (200+ probes x 3 principals x 2 backends), `tests/test_fuzz.py` |
| Hidden property used as an oracle (filter, group-by, aggregate, query) | rejected with the *same* error as a nonexistent property; typed filter validation | leakage + query tests |
| Inference from small aggregates | small-cell suppression (`min_group_size`) in declared queries | `test_query_types_validate_enforce_and_suppress` |
| Agent exceeding its caller | agents inherit the user's roles and tuples, never more; unattached agents get nothing | `tests/test_permissions.py` |
| Wrong or stale authorisation | versioned relation tuples; revocation visible to the next check; snapshot reads; cycle handling; **errors deny** | `tests/test_authz.py` (differential vs independent oracle, stateful) |
| Authz backend down / incomplete answer | fail closed on any exception, truncated list, or evaluation-budget exhaustion | `test_fail_closed_*` |
| Handle guessing / hijack / replay | 256-bit handles, stored hashed, principal-bound, single-use, expiring, re-validated at apply time | `tests/test_actions.py`, bench `denied-05` |
| Action outside its declared edit set / precondition bypass | declared `edit_set`, re-checked at apply; atomic apply with provenance | `tests/test_actions.py` |
| Unapproved or hostile schema change | model output is data; human approval bound to a digest incl. renames; destructive migrations need explicit consent; all-or-nothing | `tests/test_propose.py`, `tests/test_pushdown_queries_migrate.py` |
| Editing/deleting audit entries | hash chain + Merkle tree (RFC 6962), inclusion proofs | `tests/test_audit.py`, `tests/test_merkle.py` |
| **Truncating or rewriting the audit log (incl. recomputing every hash)** | Ed25519-signed tree heads pinned *off-box* + consistency proofs | `test_signed_heads_and_truncation_detection`, CLI test |
| Stolen token file | only SHA-256 digests stored; tokens expire and can be revoked; file mode 0600 | `tests/test_http_auth.py` |

## NOT covered (read this)
- **Pinned heads are your responsibility.** Truncation/rewrite is only detectable against a signed head you stored somewhere the log's host cannot edit. Without that, someone with full write access to the audit file can forge a self-consistent log.
- **Operator with database access** can read and edit the store directly. Ontolite governs access *through* its API, not against the process owner.
- **Timing and side channels**, covert channels, and inference beyond what small-cell suppression covers (e.g. differencing attacks across overlapping queries a principal is allowed to run).
- **Ontolite does not authenticate the stdio transport** (it trusts `--principal`). The HTTP transport authenticates bearer tokens it issued itself; it is not an OAuth/OIDC server. Put a real IdP in front for shared deployments.
- **Object existence inside an allowed type** is visible to entitled principals by design.
- **Single-process, single-writer** (SQLite) or single-connection (DuckDB); no multi-tenancy, no horizontal scale.
- **The relation engine enumerates candidates per type** (`list_objects`), linear in type size, except for inherited-over-link relations, which compile to joins. A remote engine (OpenFGA) would need the `AllowListProvider` adapter, which is defined but not implemented.
- "200+ adversarial probes return zero restricted values" is evidence against *those probes*, not a proof.
