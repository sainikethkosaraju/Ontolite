"""SQLite store (ADR-001: stdlib, zero dependencies, runs anywhere CI does)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class SQLiteStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS objects(type TEXT NOT NULL, pk TEXT NOT NULL, data TEXT NOT NULL,
            PRIMARY KEY(type, pk));
        CREATE TABLE IF NOT EXISTS links(link TEXT NOT NULL, from_pk TEXT NOT NULL, to_pk TEXT NOT NULL,
            PRIMARY KEY(link, from_pk, to_pk));
        CREATE TABLE IF NOT EXISTS provenance(seq INTEGER PRIMARY KEY AUTOINCREMENT, changeset TEXT,
            principal TEXT, type TEXT, pk TEXT, before TEXT, after TEXT);
        """)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def put(self, type_: str, pk: str, data: dict[str, Any]) -> None:
        self.conn.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?)",
                          (type_, str(pk), json.dumps(data, sort_keys=True)))

    def get(self, type_: str, pk: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT data FROM objects WHERE type=? AND pk=?",
                              (type_, str(pk))).fetchone()
        return json.loads(r[0]) if r else None

    def keys(self, type_: str) -> list[str]:
        return [r[0] for r in self.conn.execute(
            "SELECT pk FROM objects WHERE type=? ORDER BY pk", (type_,))]

    def count(self, type_: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM objects WHERE type=?", (type_,)).fetchone()[0]

    def link(self, link: str, from_pk: str, to_pk: str) -> None:
        self.conn.execute("INSERT OR IGNORE INTO links VALUES(?,?,?)",
                          (link, str(from_pk), str(to_pk)))

    def neighbours(self, link: str, from_pk: str, inverse: bool = False) -> list[str]:
        col_a, col_b = ("to_pk", "from_pk") if inverse else ("from_pk", "to_pk")
        return [r[0] for r in self.conn.execute(
            f"SELECT {col_b} FROM links WHERE link=? AND {col_a}=? ORDER BY {col_b}",
            (link, str(from_pk)))]

    def record_provenance(self, changeset: str, principal: str, type_: str, pk: str,
                          before: dict | None, after: dict) -> None:
        self.conn.execute(
            "INSERT INTO provenance(changeset,principal,type,pk,before,after) VALUES(?,?,?,?,?,?)",
            (changeset, principal, type_, str(pk), json.dumps(before, sort_keys=True),
             json.dumps(after, sort_keys=True)))

    def provenance(self) -> list[tuple]:
        return list(self.conn.execute(
            "SELECT changeset,principal,type,pk FROM provenance ORDER BY seq"))
