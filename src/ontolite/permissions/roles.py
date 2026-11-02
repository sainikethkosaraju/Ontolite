"""Role grants: role -> object type -> set of operations ('read')."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RoleBook:
    grants: dict[str, dict[str, set[str]]] = field(default_factory=dict)

    def allows(self, roles: set[str], type_: str, op: str) -> bool:
        return any(op in self.grants.get(r, {}).get(type_, set()) for r in roles)
