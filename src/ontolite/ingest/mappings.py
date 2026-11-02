"""Datasource -> object type mappings (YAML): which column feeds which property."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TableMapping:
    file: str
    object_type: str
    columns: dict[str, str]  # source column -> property
    where: dict[str, str] = field(default_factory=dict)  # source column equals value
    links: list[dict[str, str]] = field(default_factory=list)  # {link, [from_col], to_col}
    key_template: str | None = None  # builds the primary key from columns, e.g. '{adsh}|{tag}'
    where_in: dict[str, list[str]] = field(default_factory=dict)  # keep rows whose column is one of these values


def load_mappings(path: str | Path) -> list[TableMapping]:
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    return [TableMapping(m["file"], m["object_type"], m["columns"], m.get("where", {}),
                         m.get("links", []), m.get("key_template"), m.get("where_in", {})) for m in data["tables"]]
