"""Principal/role directory and the allow-list provider boundary.

Object-level authorisation lives in `ontolite.authz` (Zanzibar-style relation rewrites). This module
keeps (a) the principal/role directory used for type- and property-level RBAC and (b) the
`AllowListProvider` protocol: the seam where a remote engine (e.g. OpenFGA) would plug in. Anything
that returns an incomplete or failed answer must make reads fail closed."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

from ontolite.authz import Authz, AuthzError
from ontolite.permissions.principals import Principal
from ontolite.permissions.roles import RoleBook


class PermissionUnavailable(RuntimeError):
    """The permission backend failed or returned an incomplete answer. Reads must fail closed."""


@dataclass(frozen=True)
class AllowList:
    keys: frozenset[str] | None  # None = every object of the type
    expected: int | None  # independent count; mismatch means truncation
    reach: Any = None  # store.Reach: the allowed set as a link-reach join (keys then stay None)


class PermissionStore(Protocol):
    def principal(self, pid: str) -> Principal | None: ...
    def roles_grant(self, roles: set[str], type_: str, op: str) -> bool: ...


class AllowListProvider(Protocol):
    def allowed(self, subject: str, namespace: str, relation: str, candidates: Iterable[str]) -> AllowList: ...
    def check(self, subject: str, namespace: str, relation: str, obj_id: str) -> bool: ...


class EmbeddedAllowList:
    """AllowListProvider backed by the embedded relation engine."""

    def __init__(self, authz: Authz) -> None:
        self.authz = authz

    def allowed(self, subject: str, namespace: str, relation: str, candidates: Iterable[str]) -> AllowList:
        try:
            keys = self.authz.list_objects(namespace, relation, f"user:{subject}", candidates)
        except AuthzError as e:
            raise PermissionUnavailable(str(e)) from e
        return AllowList(frozenset(keys), len(keys))

    def reach(self, subject: str, namespace: str, relation: str, keys_of_namespace) -> Any:
        """Compile `viewer: ttu(link, rel)` chains into a Reach (roots + link hops), or None when the
        relation is not purely inherited along data links. Roots are enumerated with the generic
        engine, so semantics (exclusions, groups, wildcards) stay identical."""
        from ontolite.authz.model import TTU, LinkSet
        from ontolite.store import Reach
        user = f"user:{subject}"

        def compile_(ns: str, rel: str):
            nsdef = self.authz.ns.get(ns)
            rw = nsdef.relations.get(rel) if nsdef else None
            if not isinstance(rw, TTU):
                return None
            ls = nsdef.relations.get(rw.tupleset) if nsdef else None
            if not isinstance(ls, LinkSet):
                return None
            hop = (ls.name, not ls.inverse)
            sub = compile_(ls.target, rw.relation)
            if sub is not None:
                roots, hops = sub
                return roots, [*hops, hop]
            roots = self.authz.list_objects(ls.target, rw.relation, user, keys_of_namespace(ls.target))
            return set(roots), [hop]
        try:
            c = compile_(namespace, relation)
        except AuthzError as e:
            raise PermissionUnavailable(str(e)) from e
        if c is None:
            return None
        return Reach(frozenset(c[0]), tuple(c[1]))

    def check(self, subject: str, namespace: str, relation: str, obj_id: str) -> bool:
        try:
            return self.authz.check(f"{namespace}:{obj_id}", relation, f"user:{subject}")
        except AuthzError as e:
            raise PermissionUnavailable(str(e)) from e


class InMemoryPermissionStore:
    def __init__(self, principals: dict[str, Principal], roles: RoleBook,
                 tuples: list[tuple[str, str, str]] | None = None) -> None:
        self.principals, self.roles = principals, roles
        self.tuples = [tuple(t) for t in (tuples or [])]  # (object, relation, subject) for the authz store

    @classmethod
    def from_yaml(cls, path: str | Path) -> InMemoryPermissionStore:
        return cls.from_dict(yaml.safe_load(Path(path).read_text()))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InMemoryPermissionStore:
        roles = RoleBook({r: {t: set(ops) for t, ops in (rd.get("grants") or {}).items()}
                          for r, rd in (d.get("roles") or {}).items()})
        pr = {pid: Principal(pid, pd.get("kind", "user"), tuple(pd.get("roles", [])), pd.get("acts_for"))
              for pid, pd in (d.get("principals") or {}).items()}
        return cls(pr, roles, [tuple(t) for t in d.get("tuples", [])])  # type: ignore[misc]

    def principal(self, pid: str) -> Principal | None:
        return self.principals.get(pid)

    def roles_grant(self, roles: set[str], type_: str, op: str) -> bool:
        return self.roles.allows(roles, type_, op)
