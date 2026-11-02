# Walkthrough: Ontolite core
Request path: `mcp_server` tool -> `Retriever` (resolve principal -> `Checker.allow_list` -> data -> project) or
`ActionEngine` (plan -> validate -> transaction -> provenance + audit). Design trade-offs: generic
object/link tables (simple, no per-type DDL) at the cost of Python-side filtering; one MCP server instance
per principal (simple, auditable) instead of per-request auth. What breaks: very large types (linear scans),
audit tail truncation (see threat model), concurrent writers beyond SQLite's single-writer model.
