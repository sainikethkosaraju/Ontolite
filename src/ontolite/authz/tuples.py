"""Versioned relation tuples (SQLite). Every write bumps a revision; reads can be pinned to a
revision (snapshot reads), so a check observes one consistent state and revocations are visible
to the very next check at a newer revision.

Tuple grammar: object `type:id`, relation, subject `user:alice` | `group:eng#member` | `user:*`."""

from __future__ import annotations

import re
import sqlite3
import threading
from collections.abc import Iterable

OBJ = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:[^#\s]+$")
SUBJ = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:(\*|[^#\s]+)(#[A-Za-z_][A-Za-z0-9_]*)?$")


class TupleError(ValueError):
    pass


class TupleStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.RLock()
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS authz_meta(k TEXT PRIMARY KEY, v INTEGER);
        INSERT OR IGNORE INTO authz_meta VALUES('rev', 0);
        CREATE TABLE IF NOT EXISTS authz_tuples(obj TEXT NOT NULL, rel TEXT NOT NULL, subj TEXT NOT NULL,
            added INTEGER NOT NULL, removed INTEGER);
        CREATE INDEX IF NOT EXISTS ix_obj ON authz_tuples(obj, rel);
        CREATE INDEX IF NOT EXISTS ix_subj ON authz_tuples(subj);
        """)

    @property
    def revision(self) -> int:
        return self.db.execute("SELECT v FROM authz_meta WHERE k='rev'").fetchone()[0]

    def write(self, adds: Iterable[tuple[str, str, str]] = (), deletes: Iterable[tuple[str, str, str]] = (),
              ) -> int:
        """Atomically apply adds/deletes; returns the new revision."""
        adds, deletes = list(adds), list(deletes)
        for o, r, s in [*adds, *deletes]:
            if not OBJ.match(o) or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", r) or not SUBJ.match(s):
                raise TupleError(f"malformed tuple ({o!r}, {r!r}, {s!r})")
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                rev = self.db.execute("SELECT v FROM authz_meta WHERE k='rev'").fetchone()[0] + 1
                for o, r, s in deletes:
                    self.db.execute("UPDATE authz_tuples SET removed=? WHERE obj=? AND rel=? AND subj=? "
                                    "AND removed IS NULL", (rev, o, r, s))
                for o, r, s in adds:
                    live = self.db.execute("SELECT 1 FROM authz_tuples WHERE obj=? AND rel=? AND subj=? "
                                           "AND removed IS NULL", (o, r, s)).fetchone()
                    if not live:
                        self.db.execute("INSERT INTO authz_tuples VALUES(?,?,?,?,NULL)", (o, r, s, rev))
                self.db.execute("UPDATE authz_meta SET v=? WHERE k='rev'", (rev,))
                self.db.execute("COMMIT")
                return rev
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def read(self, obj: str, rel: str, at: int) -> list[str]:
        return [r[0] for r in self.db.execute(
            "SELECT subj FROM authz_tuples WHERE obj=? AND rel=? AND added<=? AND (removed IS NULL OR removed>?)",
            (obj, rel, at, at))]

    def all_live(self, at: int) -> list[tuple[str, str, str]]:
        return list(self.db.execute(
            "SELECT obj, rel, subj FROM authz_tuples WHERE added<=? AND (removed IS NULL OR removed>?)",
            (at, at)))

    def users(self, at: int) -> set[str]:
        """All plain (non-userset, non-wildcard) subjects ever granted something at `at`."""
        return {s for _, _, s in self.all_live(at) if "#" not in s and not s.endswith(":*")}
