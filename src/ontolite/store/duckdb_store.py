"""DuckDB backend (columnar; same pushdown API, JSON extension)."""

from __future__ import annotations

from ontolite.store.base import SQLStore


class DuckDBStore(SQLStore):
    backend = "duckdb"

    def __init__(self, path: str = ":memory:") -> None:
        import duckdb  # optional dependency: pip install ontolite[duckdb]
        self.conn = duckdb.connect(path)
        self._init()

    def _fill_keys(self, table: str, keys: list[str]) -> None:
        self.conn.execute(f"INSERT INTO {table} SELECT unnest(?)", [keys])  # set-based, not row-by-row

    def bulk_load(self, objects, links) -> None:
        if objects:
            self.conn.execute(
                "INSERT OR REPLACE INTO objects SELECT * FROM (SELECT unnest(?) a, unnest(?) b, unnest(?) c)",
                [[o[0] for o in objects], [o[1] for o in objects], [o[2] for o in objects]])
        if links:
            self.conn.execute(
                "INSERT OR IGNORE INTO links SELECT * FROM (SELECT unnest(?) a, unnest(?) b, unnest(?) c)",
                [[x[0] for x in links], [x[1] for x in links], [x[2] for x in links]])
        self.version += 1

    def _text(self, prop: str) -> str:
        return f"json_extract_string(o.data, '$.{prop}')"

    def _num(self, prop: str) -> str:
        return f"TRY_CAST(json_extract_string(o.data, '$.{prop}') AS DOUBLE)"

    def _begin(self) -> str:
        return "BEGIN TRANSACTION"
