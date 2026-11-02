"""SQL store with permission-aware pushdown.

`select` and `aggregate` take the ALLOWED key set and the VISIBLE property list and compile them
into the SQL itself: rows outside the allowed set are never scanned into the result, and only
visible properties are ever extracted from the stored JSON, so restricted values never leave the
database engine. Backends differ only in the dialect hooks below."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

NUMERIC = {"integer", "number"}
OPS = {"eq": "=", "ne": "<>", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Reach:
    """Allowed set expressed as: every object reachable from `roots` by walking `hops`.
    A hop is (link name, inverse); inverse=False walks from_pk -> to_pk. This lets a permission
    like "a fact is visible if its filing is, and a filing if its company is" be enforced as a join
    from a few hundred allowed company keys instead of a materialised list of millions of fact keys."""
    roots: frozenset[str]
    hops: tuple[tuple[str, bool], ...]


@dataclass(frozen=True)
class Cond:
    prop: str
    op: str  # eq ne gt ge lt le in
    value: Any


class SQLStore:
    conn: Any

    # ---- dialect hooks (overridden) -----------------------------------------------------
    def _text(self, prop: str) -> str: ...
    def _num(self, prop: str) -> str: ...
    def _begin(self) -> str: return "BEGIN"

    # ---- schema ---------------------------------------------------------------------------
    def _init(self) -> None:
        for stmt in (
            "CREATE TABLE IF NOT EXISTS objects(type TEXT NOT NULL, pk TEXT NOT NULL, data TEXT NOT NULL,"
            " PRIMARY KEY(type, pk))",
            "CREATE TABLE IF NOT EXISTS links(link TEXT NOT NULL, from_pk TEXT NOT NULL, to_pk TEXT NOT NULL,"
            " PRIMARY KEY(link, from_pk, to_pk))",
            "CREATE TABLE IF NOT EXISTS provenance(seq BIGINT PRIMARY KEY, changeset TEXT, principal TEXT,"
            " type TEXT, pk TEXT, before TEXT, after TEXT)",
        ):
            self.conn.execute(stmt)
        self.conn.execute("CREATE INDEX IF NOT EXISTS ix_links_to ON links(link, to_pk)")
        self.version = 0  # bumped on every data change; authz caches key on it

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.conn.execute(self._begin())
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    # ---- basic CRUD -------------------------------------------------------------------------
    def put(self, type_: str, pk: str, data: dict[str, Any]) -> None:
        self.conn.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?)",
                          (type_, str(pk), json.dumps(data, sort_keys=True)))
        self.version += 1

    def get(self, type_: str, pk: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT data FROM objects WHERE type=? AND pk=?", (type_, str(pk))).fetchone()
        return json.loads(r[0]) if r else None

    def delete(self, type_: str, pk: str) -> None:
        self.conn.execute("DELETE FROM objects WHERE type=? AND pk=?", (type_, str(pk)))
        self.version += 1

    def keys(self, type_: str) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT pk FROM objects WHERE type=? ORDER BY pk", (type_,)).fetchall()]

    def count(self, type_: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM objects WHERE type=?", (type_,)).fetchone()[0]

    def link(self, link: str, from_pk: str, to_pk: str) -> None:
        self.conn.execute("INSERT OR IGNORE INTO links VALUES(?,?,?)", (link, str(from_pk), str(to_pk)))
        self.version += 1

    def neighbours(self, link: str, from_pk: str, inverse: bool = False) -> list[str]:
        a, b = ("to_pk", "from_pk") if inverse else ("from_pk", "to_pk")
        return [r[0] for r in self.conn.execute(
            f"SELECT {b} FROM links WHERE link=? AND {a}=? ORDER BY {b}", (link, str(from_pk))).fetchall()]

    def record_provenance(self, changeset: str, principal: str, type_: str, pk: str,
                          before: dict | None, after: dict) -> None:
        self.conn.execute(
            "INSERT INTO provenance SELECT COALESCE(MAX(seq),0)+1, ?,?,?,?,?,? FROM provenance",
            (changeset, principal, type_, str(pk), json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True)))

    def provenance(self) -> list[tuple]:
        return [tuple(r) for r in self.conn.execute(
            "SELECT changeset,principal,type,pk FROM provenance ORDER BY seq").fetchall()]

    # ---- pushdown ---------------------------------------------------------------------------
    def _fill_keys(self, table: str, keys: list[str]) -> None:
        self.conn.executemany(f"INSERT INTO {table} VALUES(?)", [(k,) for k in keys])

    @contextmanager
    def _allowed_join(self, allowed: set[str] | Reach | None) -> Iterator[tuple[str, list[Any]]]:
        """Yield (join_sql, join_params) restricting `o` to the allowed set. Sets are staged in a
        temp table; a Reach stages only its roots and compiles the hops into nested IN-subqueries."""
        if allowed is None:
            yield "", []
            return
        name = "_allowed_" + uuid.uuid4().hex[:12]
        self.conn.execute(f"CREATE TEMP TABLE {name}(pk TEXT PRIMARY KEY)")
        try:
            if isinstance(allowed, Reach):
                if allowed.roots:
                    self._fill_keys(name, list(allowed.roots))
                sub, params = f"SELECT pk FROM {name}", []
                for link, inv in allowed.hops:
                    a, b = ("to_pk", "from_pk") if inv else ("from_pk", "to_pk")
                    sub = f"SELECT l.{b} AS pk FROM links l WHERE l.link = ? AND l.{a} IN ({sub})"
                    params = [link, *params]
                yield f"JOIN ({sub}) a ON a.pk = o.pk", params
            else:
                if allowed:
                    self._fill_keys(name, list(allowed))
                yield f"JOIN {name} a ON a.pk = o.pk", []
        finally:
            self.conn.execute(f"DROP TABLE IF EXISTS {name}")

    def bulk_load(self, objects: list[tuple[str, str, str]], links: list[tuple[str, str, str]]) -> None:
        """Fast path for loading many rows (JSON already serialised)."""
        self.conn.executemany("INSERT OR REPLACE INTO objects VALUES(?,?,?)", objects)
        self.conn.executemany("INSERT OR IGNORE INTO links VALUES(?,?,?)", links)
        self.version += 1

    def _col(self, prop: str, types: dict[str, str]) -> str:
        if not IDENT.match(prop):
            raise ValueError(f"bad property name {prop!r}")
        return self._num(prop) if types.get(prop) in NUMERIC else self._text(prop)

    def _where(self, conds: list[Cond], types: dict[str, str], params: list[Any]) -> str:
        out = []
        for c in conds:
            col = self._col(c.prop, types)
            if c.op == "in":
                vals = list(c.value)
                if not vals:
                    out.append("1=0")
                    continue
                out.append(f"{col} IN ({','.join('?' * len(vals))})")
                params += [self._param(v, types.get(c.prop)) for v in vals]
            elif c.op in OPS:
                out.append(f"{col} {OPS[c.op]} ?")
                params.append(self._param(c.value, types.get(c.prop)))
            else:
                raise ValueError(f"bad operator {c.op!r}")
        return " AND ".join(out)

    def _bool_text(self, v: bool) -> str:
        return "true" if v else "false"

    def _param(self, v: Any, typ: str | None) -> Any:
        if typ in NUMERIC:
            return float(v)
        if typ == "boolean":
            return self._bool_text(v if isinstance(v, bool) else str(v).lower() in {"1", "true"})
        return str(v) if v is not None else None

    @staticmethod
    def _typed(v: Any, typ: str | None) -> Any:
        if v is None:
            return None
        if typ == "integer":
            return int(float(v))
        if typ == "number":
            return float(v)
        if typ == "boolean":
            return str(v).lower() in {"1", "true"}
        return str(v)

    def select(self, type_: str, pk_prop: str, *, allowed: set[str] | Reach | None, visible: list[str],
               types: dict[str, str], conds: list[Cond] | None = None, text: str = "",
               limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        """Rows of `type_` within `allowed` (None = all), projected to `visible` properties,
        filtered by `conds` (visible properties only: the caller validates), with `text` matched
        against visible properties only."""
        props = [p for p in visible if p != pk_prop]
        sel = ["o.pk"] + [self._text(p) for p in props]
        where = ["o.type = ?"]
        with self._allowed_join(allowed) as (join, jparams):
            params: list[Any] = [*jparams, type_]
            if conds:
                where.append(self._where(conds, types, params))
            if text:
                hay = " || ' ' || ".join(f"COALESCE({self._text(p)}, '')" for p in [pk_prop, *props]) or "''"
                esc = text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                where.append(f"lower({hay}) LIKE ? ESCAPE '\\'")
                params.append(f"%{esc}%")
            sql = (f"SELECT {', '.join(sel)} FROM objects o {join} WHERE {' AND '.join(where)} "
                   f"ORDER BY o.pk LIMIT {int(limit)} OFFSET {int(offset)}")
            rows = self.conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            row: dict[str, Any] = {pk_prop: r[0]}
            for p, v in zip(props, r[1:]):
                tv = self._typed(v, types.get(p))
                if tv is not None:
                    row[p] = tv
            out.append(row)
        return out

    def aggregate(self, type_: str, *, allowed: set[str] | Reach | None, types: dict[str, str],
                  conds: list[Cond] | None = None, group_by: list[str] | None = None,
                  op: str = "count", prop: str | None = None, min_group: int = 0,
                  limit: int = 1000) -> list[dict[str, Any]]:
        """count/sum/avg/min/max (optionally grouped) inside the engine. Groups with fewer than
        `min_group` rows are dropped (small-cell suppression)."""
        if op not in {"count", "sum", "avg", "min", "max"}:
            raise ValueError(f"bad aggregate {op!r}")
        group_by = group_by or []
        agg = "COUNT(*)" if op == "count" else f"{op.upper()}({self._col(prop or '', {**types, prop or '': 'number'})})"
        gcols = [self._text(g) for g in group_by]
        sel = [*gcols, agg, "COUNT(*)"]
        where = ["o.type = ?"]
        with self._allowed_join(allowed) as (join, jparams):
            params: list[Any] = [*jparams, type_]
            if conds:
                where.append(self._where(conds, types, params))
            sql = f"SELECT {', '.join(sel)} FROM objects o {join} WHERE {' AND '.join(where)}"
            if gcols:
                sql += f" GROUP BY {', '.join(gcols)}"
            if min_group:
                sql += f" HAVING COUNT(*) >= {int(min_group)}"
            if gcols:
                sql += f" ORDER BY {', '.join(gcols)}"
            sql += f" LIMIT {int(limit)}"
            rows = self.conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            row = {g: self._typed(v, types.get(g)) for g, v in zip(group_by, r)}
            row["value"] = r[len(group_by)]
            row["n"] = r[len(group_by) + 1]
            out.append(row)
        return out
