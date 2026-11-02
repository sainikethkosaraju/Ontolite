from ontolite.store.base import Cond, Reach, SQLStore
from ontolite.store.sqlite_store import SQLiteStore


def open_store(backend: str = "sqlite", path: str = ":memory:") -> SQLStore:
    if backend == "sqlite":
        return SQLiteStore(path)
    if backend == "duckdb":
        from ontolite.store.duckdb_store import DuckDBStore
        return DuckDBStore(path)
    raise ValueError(f"unknown backend {backend!r}")


__all__ = ["Cond", "Reach", "SQLStore", "SQLiteStore", "open_store"]
