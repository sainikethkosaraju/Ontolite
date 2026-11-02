"""Wires schema, store, relation engine, audit, retrieval and actions into one handle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ontolite.actions import ActionEngine
from ontolite.audit import AuditLog
from ontolite.authz import Authz, TupleStore, parse_namespaces
from ontolite.permissions import Checker
from ontolite.permissions.rebac import (
    AllowListProvider,
    EmbeddedAllowList,
    InMemoryPermissionStore,
    PermissionStore,
)
from ontolite.retrieval import Retriever
from ontolite.schema import Schema, load_schema
from ontolite.store import SQLStore, open_store


class DataLinks:
    """Lets relation rewrites follow the same data links that queries traverse."""

    def __init__(self, store: SQLStore) -> None:
        self.store = store

    def related(self, obj_type: str, obj_id: str, link: str, inverse: bool) -> list[str]:
        return self.store.neighbours(link, obj_id, inverse=inverse)

    def version(self) -> int:
        return self.store.version


class Ontolite:
    def __init__(self, schema: Schema, store: SQLStore, perms: PermissionStore,
                 audit: AuditLog | None = None, authz_config: dict[str, Any] | None = None,
                 tuples: TupleStore | None = None, provider: AllowListProvider | None = None) -> None:
        self.schema, self.store, self.perms = schema, store, perms
        self.audit = audit or AuditLog()
        self.tuples = tuples or TupleStore()
        seed = getattr(perms, "tuples", [])
        if seed and self.tuples.revision == 0:
            self.tuples.write(adds=seed)
        self.authz = Authz(parse_namespaces(authz_config or {}), self.tuples, DataLinks(store))
        self.provider = provider or EmbeddedAllowList(self.authz)
        self._wire()

    def _wire(self) -> None:
        self.checker = Checker(self.schema, self.perms, self.provider, self.store)
        self.retriever = Retriever(self.schema, self.store, self.checker, self.audit)
        self.actions = ActionEngine(self.schema, self.store, self.checker, self.audit)

    def replace_schema(self, schema: Schema) -> None:
        self.schema = schema
        self._wire()

    @classmethod
    def open(cls, schema_path: str | Path, principals_path: str | Path, db: str = ":memory:",
             audit_path: str | Path | None = None, authz_path: str | Path | None = None,
             backend: str = "sqlite", signing_key: Any = None) -> Ontolite:
        authz_path = authz_path or Path(schema_path).with_name("authz.yaml")
        cfg = yaml.safe_load(Path(authz_path).read_text())["namespaces"] if Path(authz_path).exists() else {}
        return cls(load_schema(schema_path), open_store(backend, db),
                   InMemoryPermissionStore.from_yaml(principals_path),
                   AuditLog(audit_path, signing_key), cfg)
