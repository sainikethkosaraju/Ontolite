# Walkthrough: how a request flows
`search(alice, Fact, "revenue")`:
1. `Checker.resolve` maps the principal (agent -> its user) to roles + subject.
2. `Checker.allow_list` asks the provider for a **Reach**: Fact inherits `viewer` along data links, so the engine enumerates alice's allowed *companies* (600 of 2,000 in the benchmark) and returns roots + hops `[filings, facts]`. If the relation is not purely link-inherited it falls back to `list_objects` (a key list).
3. `Retriever` pushes `(allowed, visible properties, filters, text)` into `store.select`: the SQL joins from the staged roots through the links, extracts only visible JSON properties, and matches text against them.
4. Every outcome (allow or deny) is appended to the hash-chained, Merkle-indexed audit log.
Writes go `propose -> (approve) -> apply`; apply re-runs the plan (permissions, preconditions, edit set) inside one transaction and writes provenance. Design choices and their measured trade-offs: [ADR-001](adr/001-store.md). Where it breaks: see [threat-model.md](threat-model.md).
