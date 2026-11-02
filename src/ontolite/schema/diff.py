"""Structural schema diff: added, removed and changed types."""

from __future__ import annotations

from dataclasses import dataclass, field

from ontolite.schema.models import Schema


@dataclass
class SchemaDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def render(self) -> str:
        lines = [f"+ {x}" for x in self.added] + [f"- {x}" for x in self.removed] \
            + [f"~ {x}" for x in self.changed]
        return "\n".join(lines) or "(no changes)"


def diff_schemas(old: Schema, new: Schema) -> SchemaDiff:
    d = SchemaDiff()
    a, b = old.to_dict(), new.to_dict()
    for kind in ("objects", "links", "actions", "queries"):
        for n in sorted(set(b[kind]) - set(a[kind])):
            d.added.append(f"{kind[:-1]} {n}")
        for n in sorted(set(a[kind]) - set(b[kind])):
            d.removed.append(f"{kind[:-1]} {n}")
        for n in sorted(set(a[kind]) & set(b[kind])):
            if a[kind][n] != b[kind][n]:
                d.changed.append(f"{kind[:-1]} {n}")
    return d
