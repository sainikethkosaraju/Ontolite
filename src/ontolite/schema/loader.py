"""YAML schema loader with strict validation and clear errors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ontolite.schema.models import (
    VALUE_TYPES,
    ActionType,
    LinkType,
    ObjectType,
    Property,
    Schema,
)


class SchemaError(ValueError):
    pass


def _req(d: dict, key: str, where: str) -> Any:
    if key not in d:
        raise SchemaError(f"{where}: missing required field '{key}'")
    return d[key]


def parse_schema(data: Any) -> Schema:
    if not isinstance(data, dict):
        raise SchemaError("schema must be a mapping")
    unknown = set(data) - {"objects", "links", "actions"}
    if unknown:
        raise SchemaError(f"unknown top-level keys: {sorted(unknown)}")
    s = Schema()
    for name, od in (data.get("objects") or {}).items():
        where = f"object {name}"
        if not isinstance(od, dict):
            raise SchemaError(f"{where}: must be a mapping")
        pk = _req(od, "primary_key", where)
        props: dict[str, Property] = {}
        for pname, pd in (_req(od, "properties", where) or {}).items():
            pd = pd if isinstance(pd, dict) else {"type": pd}
            ptype = pd.get("type", "string")
            if ptype not in VALUE_TYPES:
                raise SchemaError(f"{where}.{pname}: unknown value type '{ptype}'")
            vis = pd.get("visibility")
            if vis is not None and (not isinstance(vis, list) or not vis):
                raise SchemaError(f"{where}.{pname}: visibility must be a non-empty list of roles")
            props[pname] = Property(pname, ptype, tuple(vis) if vis else None)
        if pk not in props:
            raise SchemaError(f"{where}: primary_key '{pk}' is not a declared property")
        access = od.get("access", "open")
        if access not in {"open", "relationship", "inherit"}:
            raise SchemaError(f"{where}: access must be 'open', 'relationship' or 'inherit'")
        via = od.get("inherit_via")
        if (access == "inherit") != (via is not None):
            raise SchemaError(f"{where}: inherit_via is required for (and only for) access: inherit")
        s.objects[name] = ObjectType(name, pk, props, access, via)
    for name, ld in (data.get("links") or {}).items():
        where = f"link {name}"
        lt = LinkType(name, _req(ld, "from", where), _req(ld, "to", where),
                      _req(ld, "inverse", where), ld.get("cardinality", "one_to_many"))
        for end in (lt.from_type, lt.to_type):
            if end not in s.objects:
                raise SchemaError(f"{where}: unknown object type '{end}'")
        if lt.cardinality not in {"one_to_one", "one_to_many", "many_to_many"}:
            raise SchemaError(f"{where}: bad cardinality '{lt.cardinality}'")
        s.links[name] = lt
    for o in s.objects.values():
        if o.access == "inherit":
            lt = s.links.get(o.inherit_via or "")
            if lt is None or lt.to_type != o.name:
                raise SchemaError(f"object {o.name}: inherit_via must name a link ending at {o.name}")
    for name, ad in (data.get("actions") or {}).items():
        where = f"action {name}"
        target = _req(ad, "target", where)
        if target not in s.objects:
            raise SchemaError(f"{where}: unknown target type '{target}'")
        params = dict(_req(ad, "parameters", where))
        for p, t in params.items():
            if t not in VALUE_TYPES:
                raise SchemaError(f"{where}: parameter '{p}' has unknown type '{t}'")
        edit_set = tuple(_req(ad, "edit_set", where))
        for t in edit_set:
            if t not in s.objects:
                raise SchemaError(f"{where}: edit_set names unknown type '{t}'")
        edits = tuple(_req(ad, "edits", where))
        for e in edits:
            if e.get("type") not in s.objects:
                raise SchemaError(f"{where}: edit names unknown type '{e.get('type')}'")
            for pn in e.get("set", {}):
                if pn not in s.objects[e["type"]].properties:
                    raise SchemaError(f"{where}: edit sets unknown property '{pn}'")
            kp = e.get("key_param")
            if kp not in params:
                raise SchemaError(f"{where}: edit key_param '{kp}' is not a parameter")
        roles = tuple(_req(ad, "roles", where))
        if not roles:
            raise SchemaError(f"{where}: roles must be non-empty (actions are deny-by-default)")
        s.actions[name] = ActionType(
            name, target, params, roles, edit_set, edits,
            tuple(ad.get("preconditions", [])), tuple(ad.get("approver_roles", [])),
            ad.get("description", ""))
    return s


def load_schema(path: str | Path) -> Schema:
    try:
        data = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as e:
        raise SchemaError(f"invalid YAML: {e}") from e
    return parse_schema(data)
