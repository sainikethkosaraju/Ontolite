"""Governed retrieval. Order of operations, always: resolve principal -> compute the allowed
set -> only then touch data -> project to visible properties. Any failure raises; nothing partial
is returned (fail closed). Denials are indistinguishable from absence."""

from __future__ import annotations

from typing import Any

from ontolite.audit import AuditLog
from ontolite.permissions.checks import Checker, Effective
from ontolite.permissions.rebac import PermissionUnavailable
from ontolite.schema.models import Schema
from ontolite.store import SQLiteStore

NOT_FOUND = "not found or not permitted"
MAX_LIMIT = 200


class AccessDenied(Exception):
    pass


class Retriever:
    def __init__(self, schema: Schema, store: SQLiteStore, checker: Checker, audit: AuditLog):
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

    def _project(self, type_: str, pk: str, data: dict, visible: set[str]) -> dict[str, Any]:
        out = {k: v for k, v in data.items() if k in visible}
        out[self.schema.objects[type_].primary_key] = pk
        return out

    def _candidates(self, type_: str, al) -> list[str]:
        keys = self.store.keys(type_)
        return keys if al.keys is None else [k for k in keys if k in al.keys]

    def _check_filters(self, filters: dict | None, visible: set[str], eff: Effective, op: str):
        for f in (filters or {}):
            if f not in visible:
                self.audit.append(eff.id, op, "deny:filter-on-hidden-property")
                raise AccessDenied(NOT_FOUND)  # same as an unknown property: no oracle

    # -- operations
    def get(self, pid: str, type_: str, pk: str) -> dict[str, Any]:
        eff = self._eff(pid, "get")
        al, visible = self._allowed(eff, type_, "get")
        pk = str(pk)
        if (al.keys is not None and pk not in al.keys):
            self.audit.append(pid, "get", "deny", {"type": type_, "pk": pk})
            raise AccessDenied(NOT_FOUND)
        data = self.store.get(type_, pk)
        if data is None:
            self.audit.append(pid, "get", "deny:absent", {"type": type_, "pk": pk})
            raise AccessDenied(NOT_FOUND)
        self.audit.append(pid, "get", "allow", {"type": type_, "pk": pk})
        return self._project(type_, pk, data, visible)

    def search(self, pid: str, type_: str, text: str = "", filters: dict | None = None,
               limit: int = 20) -> list[dict[str, Any]]:
        eff = self._eff(pid, "search")
        al, visible = self._allowed(eff, type_, "search")
        self._check_filters(filters, visible, eff, "search")
        limit = max(1, min(int(limit), MAX_LIMIT))
        out = []
        for pk in self._candidates(type_, al):
            data = self.store.get(type_, pk) or {}
            row = self._project(type_, pk, data, visible)
            if any(row.get(f) != v for f, v in (filters or {}).items()):
                continue
            # text matches only VISIBLE properties, so search cannot be used as an oracle
            if text and text.lower() not in " ".join(str(v) for v in row.values()).lower():
                continue
            out.append(row)
            if len(out) >= limit:
                break
        self.audit.append(pid, "search", "allow", {"type": type_, "text": text, "n": len(out)})
        return out

    def traverse(self, pid: str, type_: str, pk: str, link: str) -> list[dict[str, Any]]:
        eff = self._eff(pid, "traverse")
        self.get(pid, type_, pk)  # the source object must itself be readable
        forward = self.schema.links.get(link)
        inverse = next((lt for lt in self.schema.links.values() if lt.inverse == link), None)
        if forward and forward.from_type == type_:
            target_type, inv = forward.to_type, False
            link_name = forward.name
        elif inverse and inverse.to_type == type_:
            target_type, inv = inverse.from_type, True
            link_name = inverse.name
        else:
            self.audit.append(pid, "traverse", "deny:unknown-link")
            raise AccessDenied(NOT_FOUND)
        al, visible = self._allowed(eff, target_type, "traverse")
        out = []
        for npk in self.store.neighbours(link_name, str(pk), inverse=inv):
            if al.keys is not None and npk not in al.keys:
                continue
            data = self.store.get(target_type, npk)
            if data is not None:
                out.append(self._project(target_type, npk, data, visible))
        self.audit.append(pid, "traverse", "allow", {"type": type_, "pk": pk, "link": link})
        return out

    def query(self, pid: str, type_: str, op: str, prop: str | None = None,
              filters: dict | None = None) -> dict[str, Any]:
        """Aggregates computed ONLY over the allowed set and ONLY on visible properties."""
        eff = self._eff(pid, "query")
        al, visible = self._allowed(eff, type_, "query")
        self._check_filters(filters, visible, eff, "query")
        if op not in {"count", "sum", "avg", "min", "max"}:
            raise AccessDenied("unsupported operation")
        if op != "count":
            if prop not in visible or self.schema.objects[type_].properties[prop].type \
                    not in {"integer", "number"}:
                self.audit.append(pid, "query", "deny:property")
                raise AccessDenied(NOT_FOUND)
        vals: list[float] = []
        n = 0
        pname = prop or ""
        for pk in self._candidates(type_, al):
            row = self._project(type_, pk, self.store.get(type_, pk) or {}, visible)
            if any(row.get(f) != v for f, v in (filters or {}).items()):
                continue
            n += 1
            if op != "count" and isinstance(row.get(pname), int | float):
                vals.append(float(row[pname]))
        self.audit.append(pid, "query", "allow", {"type": type_, "op": op, "prop": prop})
        if op == "count":
            return {"op": op, "value": n}
        if not vals:
            return {"op": op, "value": None}
        value = {"sum": sum(vals), "avg": sum(vals) / len(vals), "min": min(vals),
                 "max": max(vals)}[op]
        return {"op": op, "value": value}
