"""Embedded relationship-based store: tuples (subject, relation, object), e.g.
("alice", "viewer", "Company:0000320193") and group membership ("alice", "member", "group:eu").
A tuple granted to group:eu applies to its members."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from ontolite.permissions.principals import Principal
from ontolite.permissions.roles import RoleBook


class PermissionUnavailable(RuntimeError):
    """The permission store failed or returned an incomplete answer. Reads must fail closed."""


@dataclass(frozen=True)
class AllowList:
    keys: frozenset[str] | None  # None = every object of the type
    expected: int | None  # independent count; mismatch means truncation


class PermissionStore(Protocol):
    def principal(self, pid: str) -> Principal | None: ...
    def roles_grant(self, roles: set[str], type_: str, op: str) -> bool: ...
    def allow_list(self, subject: str, type_: str) -> AllowList: ...
    def has_relation(self, subject: str, relation: str, obj: str) -> bool: ...


class InMemoryPermissionStore:
    def __init__(self, principals: dict[str, Principal], roles: RoleBook,
                 tuples: list[tuple[str, str, str]]) -> None:
        self.principals, self.roles = principals, roles
        self.tuples = [tuple(t) for t in tuples]

    @classmethod
    def from_yaml(cls, path: str | Path) -> InMemoryPermissionStore:
        return cls.from_dict(yaml.safe_load(Path(path).read_text()))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InMemoryPermissionStore:
        roles = RoleBook({r: {t: set(ops) for t, ops in (rd.get("grants") or {}).items()}
                          for r, rd in (d.get("roles") or {}).items()})
        pr = {pid: Principal(pid, pd.get("kind", "user"), tuple(pd.get("roles", [])),
                             pd.get("acts_for")) for pid, pd in (d.get("principals") or {}).items()}
        return cls(pr, roles, [tuple(t) for t in d.get("relationships", [])])  # type: ignore

    def principal(self, pid: str) -> Principal | None:
        return self.principals.get(pid)

    def roles_grant(self, roles: set[str], type_: str, op: str) -> bool:
        return self.roles.allows(roles, type_, op)

    def _subjects(self, subject: str) -> set[str]:
        groups = {o for s, r, o in self.tuples if s == subject and r == "member"}
        return {subject} | groups

    def has_relation(self, subject: str, relation: str, obj: str) -> bool:
        subs = self._subjects(subject)
        return any(s in subs and r == relation and o == obj for s, r, o in self.tuples)

    def allow_list(self, subject: str, type_: str) -> AllowList:
        subs = self._subjects(subject)
        prefix = f"{type_}:"
        keys = frozenset(o[len(prefix):] for s, r, o in self.tuples
                         if s in subs and r == "viewer" and o.startswith(prefix))
        return AllowList(keys, len(keys))
