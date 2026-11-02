"""Namespace configuration: relation definitions as userset rewrites (Zanzibar, Pang et al. 2019).

    namespaces:
      group:   {relations: {member: this}}
      company: {relations: {viewer: {union: [this, {computed: reviewer}]}, reviewer: this}}
      filing:  {relations: {parent: {link: {name: filings, inverse: true, target: company}},
                            viewer: {ttu: [parent, viewer]}}}

Rewrites: `this` (direct tuples), `{computed: rel}`, `{ttu: [tupleset, rel]}` (follow tupleset
tuples, then evaluate `rel` on each target object), `{union|intersection: [...]}`,
`{exclusion: {base: ..., subtract: ...}}`, and `{link: ...}` (a tupleset derived from the data
graph instead of stored tuples, so permissions inherit along the same links queries traverse).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Union


@dataclass(frozen=True)
class This:
    pass


@dataclass(frozen=True)
class Computed:
    relation: str


@dataclass(frozen=True)
class TTU:
    tupleset: str
    relation: str


@dataclass(frozen=True)
class Union_:
    children: tuple[Rewrite, ...]


@dataclass(frozen=True)
class Intersection:
    children: tuple[Rewrite, ...]


@dataclass(frozen=True)
class Exclusion:
    base: Rewrite
    subtract: Rewrite


@dataclass(frozen=True)
class LinkSet:
    """Tupleset backed by a data-graph link: related objects of `target` type."""
    name: str
    inverse: bool
    target: str


Rewrite = Union[This, Computed, TTU, Union_, Intersection, Exclusion, LinkSet]  # noqa: UP007


@dataclass
class Namespace:
    name: str
    relations: dict[str, Rewrite] = field(default_factory=dict)


class AuthzConfigError(ValueError):
    pass


def _parse(expr: Any, where: str) -> Rewrite:
    if expr == "this":
        return This()
    if not isinstance(expr, dict) or len(expr) != 1:
        raise AuthzConfigError(f"{where}: expected 'this' or a single-key mapping, got {expr!r}")
    (op, arg), = expr.items()
    if op == "computed":
        return Computed(str(arg))
    if op == "ttu":
        if not (isinstance(arg, list) and len(arg) == 2):
            raise AuthzConfigError(f"{where}: ttu needs [tupleset, relation]")
        return TTU(str(arg[0]), str(arg[1]))
    if op in {"union", "intersection"}:
        if not isinstance(arg, list) or not arg:
            raise AuthzConfigError(f"{where}: {op} needs a non-empty list")
        kids = tuple(_parse(a, f"{where}.{op}") for a in arg)
        return Union_(kids) if op == "union" else Intersection(kids)
    if op == "exclusion":
        if not isinstance(arg, dict) or set(arg) != {"base", "subtract"}:
            raise AuthzConfigError(f"{where}: exclusion needs base and subtract")
        return Exclusion(_parse(arg["base"], where), _parse(arg["subtract"], where))
    if op == "link":
        if not isinstance(arg, dict) or not {"name", "target"} <= set(arg):
            raise AuthzConfigError(f"{where}: link needs name and target")
        return LinkSet(str(arg["name"]), bool(arg.get("inverse", False)), str(arg["target"]))
    raise AuthzConfigError(f"{where}: unknown operator {op!r}")


def _refs(rw: Rewrite) -> list[tuple[str, str | None]]:
    """(kind, relation) dependencies inside one namespace, for validation."""
    if isinstance(rw, Computed):
        return [("computed", rw.relation)]
    if isinstance(rw, TTU):
        return [("tupleset", rw.tupleset)]
    if isinstance(rw, Union_ | Intersection):
        return [r for c in rw.children for r in _refs(c)]
    if isinstance(rw, Exclusion):
        return _refs(rw.base) + _refs(rw.subtract)
    return []


def parse_namespaces(data: dict[str, Any]) -> dict[str, Namespace]:
    out: dict[str, Namespace] = {}
    for name, nd in (data or {}).items():
        rels = (nd or {}).get("relations") or {}
        out[name] = Namespace(name, {r: _parse(e, f"{name}.{r}") for r, e in rels.items()})
    for ns in out.values():
        for r, rw in ns.relations.items():
            for kind, ref in _refs(rw):
                if ref not in ns.relations:
                    raise AuthzConfigError(f"{ns.name}.{r}: {kind} references undefined relation {ref!r}")
    return out
