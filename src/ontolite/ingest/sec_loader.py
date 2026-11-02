"""SEC Financial Statement Data Sets loader (public domain). Reads sub.txt and num.txt (+tag.txt)
via demo/sec/mappings.yaml. This module only wires the demo; mappings do the work."""

from __future__ import annotations

from pathlib import Path

from ontolite.ingest.csv_loader import load_table
from ontolite.ingest.mappings import load_mappings
from ontolite.schema.models import Schema
from ontolite.store import SQLStore


def load_sec(schema: Schema, store: SQLStore, data_dir: str | Path, mappings: str | Path,
             limit: int | None = None, progress: bool = False) -> dict[str, int]:
    counts: dict[str, int] = {}
    for m in load_mappings(mappings):
        if m.optional and not (Path(data_dir) / m.file).exists():
            continue
        counts[f"{m.file}->{m.object_type}"] = load_table(
            schema, store, m, Path(data_dir), limit=limit, progress=progress)
    return counts
