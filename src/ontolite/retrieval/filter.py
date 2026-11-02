"""Governed retrieval. Order of operations, always: resolve principal -> compute the allowed set ->
push (allowed set, visible properties) INTO the store query -> return. Hidden properties are never
extracted from storage and rows outside the allowed set are never selected. Any failure raises;
nothing partial is returned (fail closed). Denials are indistinguishable from absence."""

from __future__ import annotations

from typing import Any

from ontolite.audit import AuditLog
from ontolite.permissions.checks import Checker, Effective
from ontolite.permissions.rebac import PermissionUnavailable
from ontolite.schema.models import QueryType, Schema
from ontolite.store import Cond, SQLStore

NOT_FOUND = "not found or not permitted"
MAX_LIMIT = 200
PARAM_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "date": str}


class AccessDenied(Exception):
    pass


class Retriever:
    def __init__(self, schema: Schema, store: SQLStore, checker: Checker, audit: AuditLog):
        self.schema, self.store, self.checker, self.audit = schema, store, checker, audit

    # -- helpers
    def _eff(self, pid: str, op: str) -> Effective:
        try:
            eff = self.checker.resolve(pid)
        except PermissionUnavailable:
            self.audit.append(pid, op, "deny:unavailable")
            raise AccessDenied("service unavailable") from None
        if eff is None:
            self.audit.append(pid, op, "deny:unknown-principal")
            raise AccessDenied(NOT_FOUND)
        return eff

    def _allowed(self, eff: Effective, type_: str, op: str):
        if type_ not in self.schema.objects:
            self.audit.append(eff.id, op, "deny:unknown-type", {"type": type_})
            raise AccessDenied(NOT_FOUND)
        try:
            return self.checker.allow_list(eff, type_), self.checker.visible_properties(eff, type_)
        except PermissionUnavailable:
            self.audit.append(eff.id, op, "deny:unavailable", {"type": type_})
            raise AccessDenied("service unavailable") from None

    def _types(self, type_: str) -> dict[str, str]:
        return {n: p.type for n, p in self.schema.objects[type_].properties.items()}

    def _conds(self, type_: str, filters: dict | None, visible: set[str], eff: Effective, op: str) -> list[Cond]:
        for f in (filters or {}):
            if f not in visible:  # hidden == nonexistent: no oracle
                self.audit.append(eff.id, op, "deny:filter-on-hidden-property")
                raise AccessDenied(NOT_FOUND)
        types = self._types(type_)
        out = []
        for f, v in (filters or {}).items():
            t = types.get(f)
            try:
                if t in {"integer", "number"}:
                    if isinstance(v, bool):
                        raise ValueError
                    v = float(v)
                elif t == "boolean" and not isinstance(v, bool) and str(v).lower() not in {"true", "false", "1", "0"}:
                    raise ValueError
            except (TypeError, ValueError):
                self.audit.append(eff.id, op, "deny:bad-filter-value")
                raise AccessDenied("invalid filter value") from None
            out.append(Cond(f, "eq", v))
        return out

    @staticmethod
    def _arg(al):
        """The allowed-set argument for the store: a Reach, a key set, or None (= everything)."""
        if al.reach is not None:
            return al.reach
        return None if al.keys is None else set(al.keys)

    def _vis_list(self, type_: str, visible: set[str]) -> list[str]:
        pk = self.schema.objects[type_].primary_key
        return [pk] + sorted(p for p in visible if p != pk)

    # -- operations
    def get(self, pid: str, type_: str, pk: str) -> dict[str, Any]:
        eff = self._eff(pid, "get")
        al, visible = self._allowed(eff, type_, "get")
        pk = str(pk)
        try:
            readable = (pk in al.keys) if al.keys is not None else self.checker.can_read_object(eff, type_, pk)
        except PermissionUnavailable:
            self.audit.append(pid, "get", "deny:unavailable", {"type": type_})
            raise AccessDenied("service unavailable") from None
        if not readable:
            self.audit.append(pid, "get", "deny", {"type": type_, "pk": pk})
            raise AccessDenied(NOT_FOUND)
        rows = self.store.select(type_, self.schema.objects[type_].primary_key, allowed={pk},
                                 visible=self._vis_list(type_, visible), types=self._types(type_), limit=1)
        if not rows:
            self.audit.append(pid, "get", "deny:absent", {"type": type_, "pk": pk})
            raise AccessDenied(NOT_FOUND)
        self.audit.append(pid, "get", "allow", {"type": type_, "pk": pk})
        return rows[0]

    def search(self, pid: str, type_: str, text: str = "", filters: dict | None = None,
               limit: int = 20) -> list[dict[str, Any]]:
        eff = self._eff(pid, "search")
        al, visible = self._allowed(eff, type_, "search")
        conds = self._conds(type_, filters, visible, eff, "search")
        limit = max(1, min(int(limit), MAX_LIMIT))
        rows = self.store.select(type_, self.schema.objects[type_].primary_key,
                                 allowed=self._arg(al),
                                 visible=self._vis_list(type_, visible), types=self._types(type_),
                                 conds=conds, text=text, limit=limit)
        self.audit.append(pid, "search", "allow", {"type": type_, "text": text, "n": len(rows)})
        return rows

    def traverse(self, pid: str, type_: str, pk: str, link: str) -> list[dict[str, Any]]:
        eff = self._eff(pid, "traverse")
        self.get(pid, type_, pk)  # the source object must itself be readable
        forward = self.schema.links.get(link)
        inverse = next((lt for lt in self.schema.links.values() if lt.inverse == link), None)
        if forward and forward.from_type == type_:
            target_type, inv, link_name = forward.to_type, False, forward.name
        elif inverse and inverse.to_type == type_:
            target_type, inv, link_name = inverse.from_type, True, inverse.name
        else:
            self.audit.append(pid, "traverse", "deny:unknown-link")
            raise AccessDenied(NOT_FOUND)
        al, visible = self._allowed(eff, target_type, "traverse")
        near = set(self.store.neighbours(link_name, str(pk), inverse=inv))
        try:
            if al.keys is not None:
                near &= set(al.keys)
            elif al.reach is not None:
                near = {k for k in near if self.checker.can_read_object(eff, target_type, k)}
        except PermissionUnavailable:
            self.audit.append(pid, "traverse", "deny:unavailable")
            raise AccessDenied("service unavailable") from None
        rows = self.store.select(target_type, self.schema.objects[target_type].primary_key, allowed=near,
                                 visible=self._vis_list(target_type, visible), types=self._types(target_type),
                                 limit=MAX_LIMIT)
        self.audit.append(pid, "traverse", "allow", {"type": type_, "pk": pk, "link": link})
        return rows

    def query(self, pid: str, type_: str, op: str, prop: str | None = None,
              filters: dict | None = None) -> dict[str, Any]:
        """Ad-hoc aggregate over the allowed set, on visible properties only."""
        eff = self._eff(pid, "query")
        al, visible = self._allowed(eff, type_, "query")
        conds = self._conds(type_, filters, visible, eff, "query")
        if op not in {"count", "sum", "avg", "min", "max"}:
            raise AccessDenied("unsupported operation")
        if op != "count" and (prop not in visible or self.schema.objects[type_].properties[prop].type
                              not in {"integer", "number"}):
            self.audit.append(pid, "query", "deny:property")
            raise AccessDenied(NOT_FOUND)
        rows = self.store.aggregate(type_, allowed=self._arg(al),
                                    types=self._types(type_), conds=conds, op=op, prop=prop)
        self.audit.append(pid, "query", "allow", {"type": type_, "op": op, "prop": prop})
        v = rows[0]["value"] if rows else None
        return {"op": op, "value": (None if v is None else (v if op == "count" else float(v)))}

    def run_query(self, pid: str, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a declared QueryType. Every property it touches must be visible to the caller;
        groups below min_group_size are suppressed (small-cell suppression)."""
        eff = self._eff(pid, "run_query")
        q: QueryType | None = self.schema.queries.get(name)
        if q is None:
            self.audit.append(pid, "run_query", "deny:unknown-query")
            raise AccessDenied(NOT_FOUND)
        params = params or {}
        if set(params) != set(q.params):
            raise AccessDenied("parameters must be exactly: " + ", ".join(sorted(q.params)))
        for k, t in q.params.items():
            v = params[k]
            if (isinstance(v, bool) and t != "boolean") or not isinstance(v, PARAM_TYPES[t]):
                raise AccessDenied(f"parameter {k} must be {t}")
        al, visible = self._allowed(eff, q.object_type, "run_query")
        used = {w["property"] for w in q.where} | set(q.group_by) | (
            {q.aggregate["property"]} if q.aggregate and q.aggregate.get("property") else set())
        if not used <= visible:
            self.audit.append(pid, "run_query", "deny:property", {"query": name})
            raise AccessDenied(NOT_FOUND)  # same as an unknown query: no oracle on hidden properties
        conds = [Cond(w["property"], w.get("op", "eq"), params[w["param"]] if "param" in w else w["value"])
                 for w in q.where]
        types = self._types(q.object_type)
        allowed = self._arg(al)
        if q.aggregate is None:
            rows = self.store.select(q.object_type, self.schema.objects[q.object_type].primary_key,
                                     allowed=allowed, visible=self._vis_list(q.object_type, visible),
                                     types=types, conds=conds, limit=min(q.limit, MAX_LIMIT))
            out: dict[str, Any] = {"query": name, "rows": rows}
        else:
            rows = self.store.aggregate(q.object_type, allowed=allowed, types=types, conds=conds,
                                        group_by=list(q.group_by), op=q.aggregate["op"],
                                        prop=q.aggregate.get("property"),
                                        min_group=q.min_group_size if q.group_by else 0, limit=q.limit)
            if not q.group_by and q.min_group_size > 1 and rows and rows[0]["n"] < q.min_group_size:
                rows = []  # a whole-population aggregate over too few rows is also suppressed
            out = {"query": name, "rows": [{**{g: r[g] for g in q.group_by}, "value": r["value"]} for r in rows]}
        self.audit.append(pid, "run_query", "allow", {"query": name, "params": params, "n": len(out["rows"])})
        return out
