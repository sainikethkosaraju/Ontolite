"""Type-, object- and property-level checks. Everything is deny-by-default and fails closed.

Agents act for a user: effective roles = user's roles (intersected with the agent's own roles
if it lists any) and only the user's relationship tuples count. An agent never has more
than its caller.
"""

from __future__ import annotations

from dataclasses import dataclass

from ontolite.permissions.rebac import AllowList, PermissionStore, PermissionUnavailable
from ontolite.schema.models import ObjectType, Schema


@dataclass(frozen=True)
class Effective:
    id: str  # who is accountable (the caller id as given)
    subject: str  # whose relationship tuples apply
    roles: frozenset[str]


class Checker:
    def __init__(self, schema: Schema, store: PermissionStore, data=None) -> None:
        self.schema, self.store, self.data = schema, store, data

    def resolve(self, pid: str) -> Effective | None:
        """None means unknown principal: no access."""
        try:
            p = self.store.principal(pid)
            if p is None:
                return None
            if p.kind == "agent":
                if not p.acts_for:
                    return None
                user = self.store.principal(p.acts_for)
                if user is None or user.kind == "agent":
                    return None
                roles = set(user.roles)
                if p.roles:
                    roles &= set(p.roles)
                return Effective(pid, user.id, frozenset(roles))
            return Effective(pid, p.id, frozenset(p.roles))
        except Exception as e:
            raise PermissionUnavailable(str(e)) from e

    def can_read_type(self, eff: Effective, type_: str) -> bool:
        try:
            return self.store.roles_grant(set(eff.roles), type_, "read")
        except Exception as e:
            raise PermissionUnavailable(str(e)) from e

    def allow_list(self, eff: Effective, type_: str) -> AllowList:
        """Allowed key set, computed BEFORE any data is touched. Raises if unavailable/incomplete."""
        ot: ObjectType | None = self.schema.objects.get(type_)
        if ot is None or not self.can_read_type(eff, type_):
            return AllowList(frozenset(), 0)
        if ot.access == "open":
            return AllowList(None, None)
        if ot.access == "inherit":
            lt = self.schema.links[ot.inherit_via or ""]
            parent = self.allow_list(eff, lt.from_type)
            if parent.keys is None:
                return AllowList(None, None)
            if self.data is None:
                raise PermissionUnavailable("no data handle for inherited access")
            try:
                keys = frozenset(c for pk in parent.keys
                                 for c in self.data.neighbours(lt.name, pk))
            except Exception as e:
                raise PermissionUnavailable(str(e)) from e
            return AllowList(keys, len(keys))
        try:
            al = self.store.allow_list(eff.subject, type_)
        except Exception as e:
            raise PermissionUnavailable(str(e)) from e
        if al.keys is None or al.expected is None or len(al.keys) != al.expected:
            raise PermissionUnavailable("allow-list incomplete")
        return al

    def can_read_object(self, eff: Effective, type_: str, pk: str) -> bool:
        al = self.allow_list(eff, type_)
        return al.keys is None or str(pk) in al.keys

    def visible_properties(self, eff: Effective, type_: str) -> set[str]:
        ot = self.schema.objects[type_]
        return {n for n, p in ot.properties.items()
                if p.visibility is None or set(p.visibility) & eff.roles}

    def can_propose(self, eff: Effective, action: str) -> bool:
        a = self.schema.actions.get(action)
        return bool(a and set(a.roles) & eff.roles)

    def can_approve(self, eff: Effective, action: str) -> bool:
        a = self.schema.actions.get(action)
        return bool(a and a.approver_roles and set(a.approver_roles) & eff.roles)
