"""SQLite backend (stdlib; JSON1)."""

from __future__ import annotations

import sqlite3

from ontolite.store.base import SQLStore


class SQLiteStore(SQLStore):
    backend = "sqlite"

    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _text(self, prop: str) -> str:
        return f"CAST(json_extract(o.data, '$.{prop}') AS TEXT)"

    def _num(self, prop: str) -> str:
        return f"CAST(json_extract(o.data, '$.{prop}') AS REAL)"

    def _begin(self) -> str:
        return "BEGIN IMMEDIATE"

    def _bool_text(self, v: bool) -> str:  # json_extract renders JSON true/false as 1/0
        return "1" if v else "0"
