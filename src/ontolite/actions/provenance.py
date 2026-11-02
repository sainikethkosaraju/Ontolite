from __future__ import annotations

from ontolite.store import SQLStore


def history(store: SQLStore) -> list[tuple]:
    """(changeset ref hash, principal, type, pk) for every applied edit, in order."""
    return store.provenance()
