"""Wires schema, store, permissions, audit, retrieval and actions into one handle."""

from __future__ import annotations

from pathlib import Path

from ontolite.actions import ActionEngine
from ontolite.audit import AuditLog
from ontolite.permissions import Checker
from ontolite.permissions.rebac import InMemoryPermissionStore, PermissionStore
from ontolite.retrieval import Retriever
from ontolite.schema import Schema, load_schema
from ontolite.store import SQLiteStore


class Ontolite:
    def __init__(self, schema: Schema, store: SQLiteStore, perms: PermissionStore,
                 audit: AuditLog | None = None) -> None:
        self.schema, self.store, self.perms = schema, store, perms
        self.audit = audit or AuditLog()
        self._wire()

    def _wire(self) -> None:
        self.checker = Checker(self.schema, self.perms, self.store)
        self.retriever = Retriever(self.schema, self.store, self.checker, self.audit)
        self.actions = ActionEngine(self.schema, self.store, self.checker, self.audit)

    def replace_schema(self, schema: Schema) -> None:
        self.schema = schema
        self._wire()

    @classmethod
    def open(cls, schema_path: str | Path, principals_path: str | Path, db: str = ":memory:",
             audit_path: str | Path | None = None) -> Ontolite:
        return cls(load_schema(schema_path), SQLiteStore(db),
                   InMemoryPermissionStore.from_yaml(principals_path), AuditLog(audit_path))
