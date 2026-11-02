"""Staged actions: propose -> (approve) -> apply, atomically, with provenance.

* Handles are 256-bit random secrets, stored only as SHA-256, bound to the proposing principal,
  single-use, and expiring. Unknown / wrong-principal / expired handles are indistinguishable.
* Approvers act on a public `ref` (derived id), never the secret handle.
* Every edit must target an object type in the action's declared edit set, re-validated at
  apply time (not only at propose time).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ontolite.actions.preconditions import check_preconditions
from ontolite.audit import AuditLog
from ontolite.audit.log import digest
from ontolite.permissions.checks import Checker, Effective
from ontolite.permissions.rebac import PermissionUnavailable
from ontolite.schema.models import Schema
from ontolite.store import SQLiteStore

DEFAULT_TTL = 900.0
BAD_HANDLE = "invalid or expired handle"
TYPE_MAP = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "date": str}


class ActionDenied(Exception):
    pass


@dataclass
class ChangeSet:
    ref: str
    principal: str
    action: str
    params: dict[str, Any]
    edits: list[dict[str, Any]]
    status: str  # proposed | approved | applied | rejected
    expires_at: float
    approved_by: str | None = None
    handle: str | None = field(default=None, repr=False)  # only returned by propose()


def _h(handle: str) -> str:
    return hashlib.sha256(handle.encode()).hexdigest()


class ActionEngine:
    def __init__(self, schema: Schema, store: SQLiteStore, checker: Checker, audit: AuditLog,
                 clock: Callable[[], float] = time.time, ttl: float = DEFAULT_TTL) -> None:
        self.schema, self.store, self.checker, self.audit = schema, store, checker, audit
        self.clock, self.ttl = clock, ttl
        store.conn.execute("CREATE TABLE IF NOT EXISTS changesets(hh TEXT PRIMARY KEY, ref TEXT "
                           "UNIQUE, body TEXT NOT NULL)")

    # ---- persistence
    def _save(self, hh: str, cs: ChangeSet) -> None:
        body = {k: v for k, v in cs.__dict__.items() if k != "handle"}
        self.store.conn.execute("INSERT OR REPLACE INTO changesets VALUES(?,?,?)",
                                (hh, cs.ref, json.dumps(body, sort_keys=True)))

    def _by_handle(self, handle: str) -> tuple[str, ChangeSet] | None:
        hh = _h(str(handle))
        r = self.store.conn.execute("SELECT body FROM changesets WHERE hh=?", (hh,)).fetchone()
        return (hh, ChangeSet(**json.loads(r[0]))) if r else None

    def _by_ref(self, ref: str) -> tuple[str, ChangeSet] | None:
        r = self.store.conn.execute("SELECT hh, body FROM changesets WHERE ref=?",
                                    (str(ref),)).fetchone()
        return (r[0], ChangeSet(**json.loads(r[1]))) if r else None

    def pending_refs(self) -> list[str]:
        return [ChangeSet(**json.loads(r[0])).ref for r in self.store.conn.execute(
            "SELECT body FROM changesets") if json.loads(r[0])["status"] == "proposed"]

    # ---- helpers
    def _deny(self, pid: str, op: str, why: str, params: Any = None) -> ActionDenied:
        self.audit.append(pid, op, f"deny:{why}", params)
        return ActionDenied(why)

    def _eff(self, pid: str, op: str) -> Effective:
        try:
            eff = self.checker.resolve(pid)
        except PermissionUnavailable:
            raise self._deny(pid, op, "service unavailable") from None
        if eff is None:
            raise self._deny(pid, op, "not permitted")
        return eff

    def _plan(self, eff: Effective, action_name: str, params: dict[str, Any],
              ) -> tuple[list[dict[str, Any]], str | None]:
        """Compute edits and validate everything. Returns (edits, error)."""
        a = self.schema.actions.get(action_name)
        if a is None or not self.checker.can_propose(eff, action_name):
            return [], "not permitted"
        if set(params) != set(a.parameters):
            return [], "parameters must be exactly: " + ", ".join(sorted(a.parameters))
        for k, t in a.parameters.items():
            v = params[k]
            if isinstance(v, bool) and t != "boolean" or not isinstance(v, TYPE_MAP[t]):
                return [], f"parameter {k} must be {t}"
        edits: list[dict[str, Any]] = []
        for e in a.edits:
            if e["type"] not in a.edit_set:
                return [], f"edit on {e['type']} is outside the declared edit set"
            pk = str(params[e["key_param"]])
            try:
                readable = self.checker.can_read_object(eff, e["type"], pk)
            except PermissionUnavailable:
                return [], "service unavailable"
            if not readable:
                return [], "not permitted"  # no oracle for hidden objects
            cur = self.store.get(e["type"], pk)
            if e["type"] == a.target_type:
                err = check_preconditions(a.preconditions, cur)
                if err:
                    return [], err
            elif cur is None:
                return [], "target does not exist"
            setv = {p: (params[v[1:]] if isinstance(v, str) and v.startswith("$") else v)
                    for p, v in e.get("set", {}).items()}
            edits.append({"type": e["type"], "pk": pk, "set": setv})
        return edits, None

    # ---- API
    def propose(self, pid: str, action: str, params: dict[str, Any]) -> ChangeSet:
        eff = self._eff(pid, "propose")
        edits, err = self._plan(eff, action, params)
        if err:
            raise self._deny(pid, f"propose:{action}", err, params)
        handle = secrets.token_urlsafe(32)
        cs = ChangeSet(ref=secrets.token_hex(8), principal=pid, action=action, params=params,
                       edits=edits, status="proposed", expires_at=self.clock() + self.ttl)
        self._save(_h(handle), cs)
        self.audit.append(pid, f"propose:{action}", "allow", params, after=edits)
        cs.handle = handle
        return cs

    def approve(self, pid: str, ref: str) -> ChangeSet:
        eff = self._eff(pid, "approve")
        found = self._by_ref(ref)
        if found is None:
            raise self._deny(pid, "approve", "not found")
        hh, cs = found
        if cs.status != "proposed" or self.clock() > cs.expires_at:
            raise self._deny(pid, "approve", "not found")
        if not self.checker.can_approve(eff, cs.action):
            raise self._deny(pid, f"approve:{cs.action}", "not permitted")
        if eff.id == cs.principal or eff.subject == self.checker.resolve(cs.principal).subject:  # type: ignore[union-attr]
            raise self._deny(pid, f"approve:{cs.action}", "self-approval is not allowed")
        cs.status, cs.approved_by = "approved", pid
        self._save(hh, cs)
        self.audit.append(pid, f"approve:{cs.action}", "allow", {"ref": cs.ref})
        return cs

    def reject(self, pid: str, ref: str) -> None:
        self._eff(pid, "reject")
        found = self._by_ref(ref)
        if found is None:
            raise self._deny(pid, "reject", "not found")
        hh, cs = found
        if cs.status in {"proposed", "approved"} and (
                pid == cs.principal or self.checker.can_approve(self._eff(pid, "reject"), cs.action)):
            cs.status = "rejected"
            self._save(hh, cs)
            self.audit.append(pid, f"reject:{cs.action}", "allow", {"ref": cs.ref})
        else:
            raise self._deny(pid, "reject", "not permitted")

    def apply(self, pid: str, handle: str) -> ChangeSet:
        eff = self._eff(pid, "apply")
        found = self._by_handle(handle)
        # unknown, other principal's, spent and expired handles all look identical
        if (found is None or found[1].principal != pid or found[1].status not in
                {"proposed", "approved"} or self.clock() > found[1].expires_at):
            raise self._deny(pid, "apply", BAD_HANDLE)
        hh, cs = found
        a = self.schema.actions[cs.action]
        if a.approver_roles and cs.status != "approved":
            raise self._deny(pid, f"apply:{cs.action}", "approval required")
        edits, err = self._plan(eff, cs.action, cs.params)  # re-validate at apply time
        if err:
            raise self._deny(pid, f"apply:{cs.action}", err)
        if edits != cs.edits:
            raise self._deny(pid, f"apply:{cs.action}", "state changed since proposal")
        before = {}
        try:
            with self.store.transaction():
                for e in edits:
                    cur = self.store.get(e["type"], e["pk"]) or {}
                    new = {**cur, **e["set"]}
                    before[f"{e['type']}:{e['pk']}"] = cur
                    self.store.put(e["type"], e["pk"], new)
                    self.store.record_provenance(cs.ref, pid, e["type"], e["pk"], cur, new)
                cs.status = "applied"
                self._save(hh, cs)
        except Exception:
            self.audit.append(pid, f"apply:{cs.action}", "error:rolled-back", cs.params)
            raise
        self.audit.append(pid, f"apply:{cs.action}", "allow", cs.params,
                          before=before, after=digest(edits))
        return cs
