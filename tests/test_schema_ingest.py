import csv

import pytest

from ontolite.schema import SchemaError, diff_schemas, load_schema, parse_schema

from .conftest import DEMO

BASE = {"objects": {"A": {"primary_key": "id", "properties": {"id": {"type": "string"}}}}}


@pytest.mark.parametrize("bad,msg", [
    ({"objects": {"A": {"properties": {"id": {}}}}}, "primary_key"),
    ({"objects": {"A": {"primary_key": "x", "properties": {"id": {}}}}}, "not a declared"),
    ({"objects": {"A": {"primary_key": "id", "properties": {"id": {"type": "blob"}}}}}, "value type"),
    ({"objects": {"A": {"primary_key": "id", "properties": {"id": {}}, "access": "x"}}}, "access"),
    ({**BASE, "links": {"l": {"from": "A", "to": "Z", "inverse": "i"}}}, "unknown object"),
    ({**BASE, "bogus": 1}, "unknown top-level"),
    ({**BASE, "actions": {"a": {"target": "A", "parameters": {"p": "string"}, "roles": [],
                                "edit_set": ["A"], "edits": []}}}, "roles"),
    ({**BASE, "actions": {"a": {"target": "A", "parameters": {"p": "string"}, "roles": ["r"],
                                "edit_set": ["A"],
                                "edits": [{"type": "A", "key_param": "nope"}]}}}, "key_param"),
    ("not a mapping", "mapping"),
])
def test_invalid_schemas_rejected(bad, msg):
    with pytest.raises(SchemaError, match=msg):
        parse_schema(bad)


def test_demo_schema_loads_and_diff():
    s = load_schema(DEMO / "schema.yaml")
    assert set(s.objects) == {"Company", "Filing", "Concept", "Fact"}
    assert diff_schemas(s, s).empty
    d = s.to_dict()
    d["objects"]["Concept"]["properties"]["extra"] = {"type": "string", "visibility": None}
    raw = {"objects": {n: {"primary_key": o["primary_key"], "access": o["access"],
                           "properties": o["properties"]} for n, o in d["objects"].items()
                       if n == "Concept"}}
    new = parse_schema(raw)
    diff = diff_schemas(s, new)
    assert "object Company" in " ".join(diff.removed) and "object Concept" in " ".join(diff.changed)
    assert diff_schemas(new, s).added


def test_row_counts_match_source(rt):
    def rows(name):
        with open(DEMO / "sample" / name, newline="") as f:
            return list(csv.DictReader(f, delimiter="\t"))
    assert rt.store.count("Company") == len({r["cik"] for r in rows("sub.txt")})
    assert rt.store.count("Filing") == len(rows("sub.txt"))
    assert rt.store.count("Fact") == len(rows("num.txt"))
    assert rt.store.count("Concept") == len(rows("tag.txt"))
    assert rt.store.get("Company", "0000320193")["risk_rating"].startswith("SENTINEL")
