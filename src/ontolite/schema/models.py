"""Schema model: object, link, action types and value types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VALUE_TYPES = {"string", "integer", "number", "boolean", "date"}


@dataclass(frozen=True)
class Property:
    name: str
    type: str = "string"
    # Roles allowed to see this property. None = anyone who may read the object.
    visibility: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ObjectType:
    name: str
    primary_key: str
    properties: dict[str, Property]
    # "open": type-level read grant is enough. "relationship": needs a relationship tuple.
    access: str = "open"  # open | relationship | inherit
    inherit_via: str | None = None  # for "inherit": forward link from the parent type


@dataclass(frozen=True)
class LinkType:
    name: str  # forward name, e.g. "filings"
    from_type: str
    to_type: str
    inverse: str  # name in the other direction, e.g. "company"
    cardinality: str = "one_to_many"


@dataclass(frozen=True)
class ActionType:
    name: str
    target_type: str
    parameters: dict[str, str]  # param name -> value type; "key" is the target's primary key
    roles: tuple[str, ...]  # roles that may propose
    edit_set: tuple[str, ...]  # object types this action may change
    edits: tuple[dict[str, Any], ...]  # [{"type": T, "key_param": p, "set": {prop: value|"$param"}}]
    preconditions: tuple[dict[str, Any], ...] = ()  # [{"property": p, "not_equals"|"equals": v}]
    approver_roles: tuple[str, ...] = ()  # if non-empty, a different principal must approve
    description: str = ""


@dataclass
class Schema:
    objects: dict[str, ObjectType] = field(default_factory=dict)
    links: dict[str, LinkType] = field(default_factory=dict)
    actions: dict[str, ActionType] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Canonical dict form (used by diff and tests)."""
        return {
            "objects": {
                n: {"primary_key": o.primary_key, "access": o.access, "inherit_via": o.inherit_via,
                    "properties": {p.name: {"type": p.type,
                                            "visibility": list(p.visibility) if p.visibility else None}
                                   for p in o.properties.values()}}
                for n, o in sorted(self.objects.items())},
            "links": {n: {"from": link.from_type, "to": link.to_type, "inverse": link.inverse,
                          "cardinality": link.cardinality}
                      for n, link in sorted(self.links.items())},
            "actions": {n: {"target": a.target_type, "parameters": dict(a.parameters),
                            "roles": list(a.roles), "edit_set": list(a.edit_set),
                            "edits": [dict(e) for e in a.edits],
                            "preconditions": [dict(p) for p in a.preconditions],
                            "approver_roles": list(a.approver_roles)}
                        for n, a in sorted(self.actions.items())},
        }
