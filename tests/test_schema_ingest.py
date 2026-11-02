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


def test_bulk_ingest_filters_tolerates_missing_columns_and_is_fast(tmp_path):
    """Regression for a real failure: the first live SEC run spent minutes in a per-row get+put loop. 100,000 fact
    rows must load in batches, honour a tag allow-list, and a `where` on an ABSENT column must not drop rows."""
    import time

    from ontolite.ingest.csv_loader import load_table
    from ontolite.ingest.mappings import TableMapping
    from ontolite.schema import load_schema
    from ontolite.store import SQLiteStore
    schema = load_schema(DEMO / "schema.yaml")
    rows = ["adsh\ttag\tversion\tddate\tqtrs\tuom\tvalue"]
    tags = ["Revenues", "Noise1", "Assets", "Noise2"]
    for i in range(100_000):
        rows.append(f"0000{i % 500:06d}-26-{i % 7:06d}\t{tags[i % 4]}\tv\t2026{i % 12 + 1:02d}01\t{i % 3}\tUSD\t{i}")
    (tmp_path / "num.txt").write_text("\n".join(rows) + "\n")
    m = TableMapping("num.txt", "Fact", {"adsh": "adsh", "tag": "tag", "ddate": "ddate", "value": "value", "uom": "uom"},
                     where={"coreg": ""}, links=[{"link": "facts", "from_col": "adsh", "to_template": "{adsh}|{tag}|{ddate}|{qtrs}"}],
                     key_template="{adsh}|{tag}|{ddate}|{qtrs}", where_in={"tag": ["Revenues", "Assets"]})
    store = SQLiteStore()
    t0 = time.time()
    n = load_table(schema, store, m, tmp_path)
    assert n == 50_000 and store.count("Fact") <= 50_000 and store.count("Fact") > 0
    assert time.time() - t0 < 60
    assert {r["tag"] for r in store.select("Fact", "id", allowed=None, visible=["id", "tag"],
                                           types={"tag": "string"}, limit=50)} <= {"Revenues", "Assets"}
    store2 = SQLiteStore()
    assert load_table(schema, store2, m, tmp_path, limit=10) == 10          # limit still honoured
