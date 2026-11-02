"""Schema migrations: diff -> plan -> validated, transactional apply.

Every data-touching step is validated against ALL existing rows BEFORE anything is written (type
coercions, defaults), then applied in one transaction; any failure rolls the whole migration back.
Destructive steps (dropping data, lossy narrowing) need an explicit `allow_destructive`."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ontolite.schema.models import Schema
from ontolite.store import SQLStore

DATE = re.compile(r"^\d{4}-?\d{2}-?\d{2}$")


class MigrationError(Exception):
    pass


@dataclass
class Step:
    kind: str
    type: str = ""
    prop: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    destructive: bool = False

    def __str__(self) -> str:
        bang = " [DESTRUCTIVE]" if self.destructive else ""
        return f"{self.kind} {self.type}{'.' + self.prop if self.prop else ''} {self.detail or ''}{bang}".strip()


@dataclass
class Migration:
    steps: list[Step] = field(default_factory=list)

    @property
    def destructive(self) -> bool:
        return any(s.destructive for s in self.steps)

    def describe(self) -> str:
        return "\n".join(str(s) for s in self.steps) or "(no changes)"


def coerce(value: Any, to: str) -> Any:
    """Strict, lossless coercion; raises ValueError when a value cannot be represented."""
    if value is None:
        return None
    if to == "string":
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)
    if to == "integer":
        if isinstance(value, bool):
            raise ValueError(f"cannot convert boolean {value!r} to integer")
        f = float(value)
        if f != int(f):
            raise ValueError(f"{value!r} is not integral")
        return int(f)
    if to == "number":
        if isinstance(value, bool):
            raise ValueError(f"cannot convert boolean {value!r} to number")
        return float(value)
    if to == "boolean":
        if isinstance(value, bool):
            return value
        if str(value).lower() in {"true", "1"}:
            return True
        if str(value).lower() in {"false", "0"}:
            return False
        raise ValueError(f"{value!r} is not a boolean")
    if to == "date":
        if not DATE.match(str(value)):
            raise ValueError(f"{value!r} is not a date")
        return str(value)
    raise ValueError(f"unknown type {to}")


LOSSY = {("number", "integer"), ("string", "integer"), ("string", "number"), ("string", "boolean"),
         ("string", "date"), ("number", "boolean"), ("integer", "boolean")}


def plan(old: Schema, new: Schema, renames: dict[str, str] | None = None) -> Migration:
    """`renames` maps "Type.old_prop" -> "new_prop" (a rename is not inferable from a diff)."""
    renames = renames or {}
    m = Migration()
    for t in sorted(set(new.objects) - set(old.objects)):
        m.steps.append(Step("add_object_type", t))
    for t in sorted(set(old.objects) - set(new.objects)):
        m.steps.append(Step("drop_object_type", t, destructive=True))
    for t in sorted(set(old.objects) & set(new.objects)):
        o, n = old.objects[t], new.objects[t]
        if o.primary_key != n.primary_key:
            raise MigrationError(f"{t}: changing the primary key is not supported")
        renamed_from = {new_name: key.split(".", 1)[1] for key, new_name in renames.items()
                        if key.startswith(t + ".")}
        for p in sorted(n.properties):
            if p in renamed_from and renamed_from[p] in o.properties:
                m.steps.append(Step("rename_property", t, p, {"from": renamed_from[p]}))
                src = o.properties[renamed_from[p]]
                if src.type != n.properties[p].type:
                    m.steps.append(Step("change_type", t, p, {"from": src.type, "to": n.properties[p].type},
                                        (src.type, n.properties[p].type) in LOSSY))
            elif p not in o.properties:
                m.steps.append(Step("add_property", t, p, {"default": n.properties[p].default}))
            elif o.properties[p].type != n.properties[p].type:
                pair = (o.properties[p].type, n.properties[p].type)
                m.steps.append(Step("change_type", t, p, {"from": pair[0], "to": pair[1]}, pair in LOSSY))
        gone = set(o.properties) - set(n.properties) - set(renamed_from.values())
        for p in sorted(gone):
            m.steps.append(Step("drop_property", t, p, destructive=True))
    for name in sorted(set(old.links) - set(new.links)):
        m.steps.append(Step("drop_link", prop=name, destructive=True))
    for name in sorted(set(new.links) - set(old.links)):
        m.steps.append(Step("add_link", prop=name))
    od, nd = old.to_dict(), new.to_dict()
    for kind in ("actions", "queries"):
        for name in sorted(set(od[kind]) | set(nd[kind])):
            if od[kind].get(name) != nd[kind].get(name):
                m.steps.append(Step("metadata", prop=f"{kind[:-1]} {name}"))
    return m


def apply(migration: Migration, old: Schema, new: Schema, store: SQLStore,
          allow_destructive: bool = False, dry_run: bool = False) -> dict[str, int]:
    if migration.destructive and not allow_destructive:
        raise MigrationError("migration is destructive; re-run with explicit allow_destructive")
    # ---- phase 1: compute every new row in memory; nothing is written yet
    edits: dict[tuple[str, str], dict[str, Any] | None] = {}
    drops_links: list[str] = []
    touched: dict[str, int] = {}

    def current(t: str, k: str) -> dict[str, Any]:
        key = (t, k)
        if key not in edits:
            edits[key] = store.get(t, k) or {}
        return edits[key]  # type: ignore[return-value]

    for s in migration.steps:
        if s.kind == "drop_object_type":
            for k in store.keys(s.type):
                edits[(s.type, k)] = None
                touched[s.kind] = touched.get(s.kind, 0) + 1
        elif s.kind in {"add_property", "rename_property", "change_type", "drop_property"}:
            for k in store.keys(s.type):
                row = current(s.type, k)
                if row is None:
                    continue
                if s.kind == "add_property":
                    d = s.detail.get("default")
                    if d is not None and s.prop not in row:
                        row[s.prop] = coerce(d, new.objects[s.type].properties[s.prop].type)
                        touched[s.kind] = touched.get(s.kind, 0) + 1
                elif s.kind == "rename_property":
                    src = s.detail["from"]
                    if src in row:
                        row[s.prop] = row.pop(src)
                        touched[s.kind] = touched.get(s.kind, 0) + 1
                elif s.kind == "change_type":
                    if s.prop in row:
                        try:
                            row[s.prop] = coerce(row[s.prop], s.detail["to"])
                        except (ValueError, TypeError) as e:
                            raise MigrationError(f"{s.type}[{k}].{s.prop}: {e}") from None
                        touched[s.kind] = touched.get(s.kind, 0) + 1
                else:
                    if s.prop in row:
                        del row[s.prop]
                        touched[s.kind] = touched.get(s.kind, 0) + 1
        elif s.kind == "drop_link":
            drops_links.append(s.prop)
    if dry_run:
        return touched
    # ---- phase 2: one transaction
    with store.transaction():
        for (t, k), row in edits.items():
            if row is None:
                store.delete(t, k)
            else:
                store.put(t, k, row)
        for lk in drops_links:
            store.conn.execute("DELETE FROM links WHERE link=?", (lk,))
        store.version += 1
    return touched
