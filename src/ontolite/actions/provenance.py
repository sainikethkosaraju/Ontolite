from __future__ import annotations

from ontolite.store import SQLiteStore


def history(store: SQLiteStore) -> list[tuple]:
    """(changeset ref hash, principal, type, pk) for every applied edit, in order."""
    return store.provenance()
