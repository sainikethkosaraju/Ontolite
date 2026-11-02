"""Delimited-file loader (CSV/TSV) driven by mappings. Values are coerced per schema type."""

from __future__ import annotations

import csv
from pathlib import Path

from ontolite.ingest.mappings import TableMapping
from ontolite.schema.models import Schema
from ontolite.store import SQLStore

csv.field_size_limit(10_000_000)


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


def load_table(schema: Schema, store: SQLStore, m: TableMapping, base: Path,
               delimiter: str | None = None, limit: int | None = None) -> int:
    path = base / m.file
    delim = delimiter or ("\t" if path.suffix in {".tsv", ".txt"} else ",")
    ot = schema.objects[m.object_type]
    n = 0
    with path.open(newline="", encoding="utf-8") as f, store.transaction():
        for row in csv.DictReader(f, delimiter=delim):
            if any(row.get(c) != v for c, v in m.where.items()):
                continue
            data = {prop: _coerce(row.get(col, ""), ot.properties[prop].type)
                    for col, prop in m.columns.items()}
            if m.key_template:
                data[ot.primary_key] = m.key_template.format(**row)
            pk = data.get(ot.primary_key)
            if pk is None:
                continue
            existing = store.get(m.object_type, str(pk)) or {}
            store.put(m.object_type, str(pk), {**existing, **{k: v for k, v in data.items()
                                                              if v is not None}})
            for lk in m.links:
                to_val = lk["to_template"].format(**row) if "to_template" in lk else row.get(lk["to_col"])
                if to_val:
                    store.link(lk["link"], str(row[lk["from_col"]]) if "from_col" in lk
                               else str(pk), str(to_val))
            n += 1
            if limit and n >= limit:
                break
    return n
