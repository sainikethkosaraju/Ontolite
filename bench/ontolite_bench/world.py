"""A fresh, isolated Ontolite world per trial (blueprint: isolate every trial in a fresh store)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ontolite.ingest.sec_loader import load_sec
from ontolite.permissions.checks import Checker
from ontolite.runtime import Ontolite

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo" / "sec"
BENCH = ROOT / "demo" / "bench"
SENTINELS = ["SENTINEL", "SECRETCO", "0000999999"]


class PermissiveChecker(Checker):
    """Deliberately BROKEN governance (everything allowed) used only to prove the graders can fail."""
    def can_read_type(self, eff, type_): return True
    def visible_properties(self, eff, type_): return set(self.schema.objects[type_].properties)
    def can_propose(self, eff, action): return True
    def can_approve(self, eff, action): return True
    def can_read_object(self, eff, type_, pk): return True
    def allow_list(self, eff, type_):
        from ontolite.permissions.rebac import AllowList
        return AllowList(None, None)


class World:
    def __init__(self, permissive: bool = False, mutation: str | None = None) -> None:
        permissive = permissive or mutation == "permissive"
        self.mutation = mutation
        self.rt = Ontolite.open(DEMO / "schema.yaml", BENCH / "principals.yaml", authz_path=DEMO / "authz.yaml")
        load_sec(self.rt.schema, self.rt.store, BENCH / "data", DEMO / "mappings.yaml")
        if permissive:
            self.rt.checker = PermissiveChecker(self.rt.schema, self.rt.perms, self.rt.provider, self.rt.store)
            self.rt.retriever.checker = self.rt.checker
            self.rt.actions.checker = self.rt.checker
        if mutation == "no_handle_binding":          # BROKEN: any principal may use any handle
            real_apply = self.rt.actions.apply

            def apply_anyone(pid, handle):
                found = self.rt.actions._by_handle(handle)
                if found:
                    hh, cs = found
                    cs.principal = pid
                    self.rt.actions._save(hh, cs)
                return real_apply(pid, handle)
            self.rt.actions.apply = apply_anyone  # type: ignore[method-assign]
        if mutation == "no_preconditions":           # BROKEN: business rules are not enforced
            import ontolite.actions.engine as eng
            self._saved_pre = eng.check_preconditions
            eng.check_preconditions = lambda *a, **k: None
        self.initial = self.snapshot()
        self.tool_outputs: list[str] = []
        self.calls: list[dict[str, Any]] = []

    def close(self) -> None:
        if getattr(self, "_saved_pre", None):
            import ontolite.actions.engine as eng
            eng.check_preconditions = self._saved_pre

    def snapshot(self) -> dict[str, Any]:
        s = self.rt.store
        return {t: {k: s.get(t, k) for k in s.keys(t)} for t in ("Company", "Filing", "Fact", "Concept")}

    def unchanged(self) -> bool:
        return self.snapshot() == self.initial

    def truth(self, type_: str, key: str) -> dict[str, Any]:
        """Ground truth straight from storage, bypassing governance (graders only)."""
        return self.rt.store.get(type_, key) or {}

    def log(self, name: str, args: dict, out: Any) -> str:
        text = json.dumps(out, default=str)
        self.calls.append({"tool": name, "args": args})
        self.tool_outputs.append(text)
        return text
