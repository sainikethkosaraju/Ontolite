"""A model proposes a new full schema as YAML. The output is untrusted DATA: it is parsed with
safe_load, validated by the schema loader, and diffed. It is never executed and has no way to
mark itself approved (approval state lives outside the model output)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass

import yaml

from ontolite.schema import Schema, SchemaDiff, SchemaError, diff_schemas, parse_schema


@dataclass
class SchemaProposal:
    id: str
    new_schema: Schema
    diff: SchemaDiff
    digest: str
    status: str = "pending"  # pending | approved | rejected | applied
    approved_by: str | None = None
    renames: dict[str, str] | None = None  # untrusted hint, shown to and approved by the human


def schema_digest(s: Schema, renames: dict[str, str] | None = None) -> str:
    body = {"schema": s.to_dict(), "renames": renames or {}}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def propose_schema_change(model: Callable[[str], str], current: Schema, request: str,
                          ) -> SchemaProposal:
    prompt = f"Propose a new schema as YAML for this request: {request}"
    text = model(prompt)
    renames: dict[str, str] = {}
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and "renames" in data:
            r = data.pop("renames")
            if not isinstance(r, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in r.items()):
                raise SchemaError("renames must map 'Type.old' to 'new' strings")
            renames = dict(r)
        new = parse_schema(data)
    except (yaml.YAMLError, SchemaError) as e:
        raise SchemaError(f"model output rejected: {e}") from e
    d = diff_schemas(current, new)
    dig = schema_digest(new, renames)
    return SchemaProposal(id=dig[:12], new_schema=new, diff=d, digest=dig, renames=renames or None)
