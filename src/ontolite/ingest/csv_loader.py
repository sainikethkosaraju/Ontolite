"""Delimited-file loader (CSV/TSV) driven by mappings. Values are coerced per schema type.

Two paths. Tables WITH a `key_template` (fact-like, one row = one object, millions of rows) are streamed in
batches through `store.bulk_load`. Tables without one (companies, filings, concepts) are small and are
MERGED per row, so several files can contribute properties to the same object (e.g. internal annotations)."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from ontolite.ingest.mappings import TableMapping
from ontolite.schema.models import Schema
from ontolite.store import SQLStore

csv.field_size_limit(10_000_000)
BATCH = 20_000


def _coerce(v: str, t: str):
    if v == "" or v is None:
        return None
    if t == "integer":
        return int(float(v))
    if t == "number":
        return float(v)
    if t == "boolean":
        return v.strip().lower() in {"1", "true", "yes"}
    return v


def _keep(row: dict[str, str], m: TableMapping) -> bool:
    # A condition on a column the file does not have is ignored (older/newer file layouts), never "drop everything".
    if any(c in row and row[c] != v for c, v in m.where.items()):
        return False
    return all(c not in row or row[c] in allowed for c, allowed in m.where_in.items())


def load_table(schema: Schema, store: SQLStore, m: TableMapping, base: Path,
               delimiter: str | None = None, limit: int | None = None, progress: bool = False) -> int:
    path = base / m.file
    delim = delimiter or ("\t" if path.suffix in {".tsv", ".txt"} else ",")
    ot = schema.objects[m.object_type]
    bulk = bool(m.key_template)
    objs: list[tuple[str, str, str]] = []
    links: list[tuple[str, str, str]] = []
    n = 0

    def flush() -> None:
        if objs or links:
            store.bulk_load(objs, links)
            objs.clear()
            links.clear()

    with path.open(newline="", encoding="utf-8") as f, store.transaction():
        for row in csv.DictReader(f, delimiter=delim):
            if not _keep(row, m):
                continue
            data = {prop: _coerce(row.get(col, ""), ot.properties[prop].type) for col, prop in m.columns.items()}
            if m.key_template:
                data[ot.primary_key] = m.key_template.format(**row)
            pk = data.get(ot.primary_key)
            if pk is None:
                continue
            clean = {k: v for k, v in data.items() if v is not None}
            if bulk:
                objs.append((m.object_type, str(pk), json.dumps(clean, sort_keys=True)))
            else:
                existing = store.get(m.object_type, str(pk)) or {}
                store.put(m.object_type, str(pk), {**existing, **clean})
            for lk in m.links:
                to_val = lk["to_template"].format(**row) if "to_template" in lk else row.get(lk["to_col"])
                if to_val:
                    frm = str(row[lk["from_col"]]) if "from_col" in lk else str(pk)
                    if bulk:
                        links.append((lk["link"], frm, str(to_val)))
                    else:
                        store.link(lk["link"], frm, str(to_val))
            n += 1
            if bulk and len(objs) >= BATCH:
                flush()
                if progress:
                    print(f"  {m.file} -> {m.object_type}: {n:,} rows", file=sys.stderr, flush=True)
            if limit and n >= limit:
                break
        flush()
    return n
