# Threat model
**Protects against:** an agent (or user) reading properties/objects/links it is not entitled to
(via get, search, filters, traversal, aggregates); acting outside its caller's authority; forging,
guessing, replaying or reusing change-set handles; a model-written schema changing the system
without human approval; undetected edits to or mid-log deletion of audit entries.

**Mechanisms:** allowed set computed before data is touched; property projection; search text
matches only visible properties; filters on hidden properties are rejected with the same error as
nonexistent properties; denials equal absence (`not found or not permitted`); agents inherit the
caller's roles/tuples and never more (unattached agents get nothing); permission-store errors or
incomplete allow-lists fail closed; handles are 256-bit, stored as SHA-256, principal-bound,
single-use, expiring; approvals use a separate public `ref`; edits re-validated at apply time
against the declared edit set; hash-chained audit.

**Not covered (read this):**
- Tail truncation of the audit log is undetectable unless you pin the head hash elsewhere (`audit verify --head`).
- The audit file is not signed: someone who can rewrite the whole file and recompute every hash can forge a valid chain.
- Timing/side channels, and leakage via values a user is allowed to see (e.g. inference from permitted aggregates).
- Small-cell aggregate disclosure: aggregates over a tiny allowed set can reveal individual values the user may already see, but no differential-privacy guarantee is made.
- Object existence inside an allowed type is visible to entitled principals by design.
- Single-process SQLite; no multi-tenancy, no network authentication: the MCP server trusts the `--principal` it was started with. Put real authN in front for any shared deployment.
- Not a security product: "tested against 200+ probes" is evidence, not proof.
