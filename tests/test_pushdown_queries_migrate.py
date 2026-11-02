import json

import pytest

from ontolite.propose import ApprovalGate, MockModel, NotApproved, propose_schema_change
from ontolite.retrieval import AccessDenied
from ontolite.schema import SchemaError, parse_schema
from ontolite.schema.migrate import Migration, MigrationError, apply, coerce, plan
from ontolite.store import Cond, Reach, open_store

from .conftest import DEMO

TYPES = {"id": "string", "name": "string", "v": "number", "secret": "string", "flag": "boolean"}


def small(backend):
    s = open_store(backend)
    with s.transaction():
        for i in range(8):
            s.put("T", str(i), {"id": str(i), "name": f"n{i % 3}", "v": i * 1.5, "secret": "S3CRET", "flag": i % 2 == 0})
        for i in range(8):
            s.link("child", str(i // 4), str(i))
    return s


@pytest.mark.parametrize("backend", ["sqlite", "duckdb"])
def test_backends_agree_and_never_read_hidden_columns(backend):
    s = small(backend)
    rows = s.select("T", "id", allowed={"1", "2", "4", "5"}, visible=["id", "name", "v", "flag"], types=TYPES,
                    conds=[Cond("v", "ge", 2)], text="n")
    assert [r["id"] for r in rows] == ["2", "4", "5"] and all("secret" not in r for r in rows)
    assert s.select("T", "id", allowed=None, visible=["id"], types=TYPES, text="S3CRET") == []   # hidden: unsearchable
    assert s.select("T", "id", allowed=set(), visible=["id"], types=TYPES) == []
    agg = s.aggregate("T", allowed=None, types=TYPES, group_by=["name"], op="sum", prop="v", min_group=3)
    assert {r["name"]: r["n"] for r in agg} == {"n0": 3, "n1": 3} or len(agg) == 2   # n2 has only 2 rows: suppressed
    assert all(r["n"] >= 3 for r in agg)
    assert s.select("T", "id", allowed=None, visible=["id", "flag"], types=TYPES, conds=[Cond("flag", "eq", True)],
                    limit=50)[0]["flag"] is True


@pytest.mark.parametrize("backend", ["sqlite", "duckdb"])
def test_reach_equals_the_materialised_key_set(backend):
    s = small(backend)
    for roots in [{"0"}, {"1"}, {"0", "1"}, set(), {"9"}]:
        reach = Reach(frozenset(roots), (("child", False),))
        keyset = {c for r in roots for c in s.neighbours("child", r)}
        a = s.select("T", "id", allowed=reach, visible=["id", "v"], types=TYPES, limit=100)
        b = s.select("T", "id", allowed=keyset, visible=["id", "v"], types=TYPES, limit=100)
        assert a == b
        assert s.aggregate("T", allowed=reach, types=TYPES, op="sum", prop="v") == \
            s.aggregate("T", allowed=keyset, types=TYPES, op="sum", prop="v")
    inv = Reach(frozenset({"3"}), (("child", True),))     # inverse hop walks child -> parent ("3" is a child of "0")
    assert [r["id"] for r in s.select("T", "id", allowed=inv, visible=["id"], types=TYPES)] == ["0"]


def test_compiled_reach_matches_generic_engine_for_every_principal(rt_any):
    for who in ["alice", "walter", "rita", "agent-alice", "agent-rita", "lena", "orphan-agent"]:
        eff = rt_any.checker.resolve(who)
        if eff is None:
            continue
        for t in ("Filing", "Fact"):
            ot = rt_any.schema.objects[t]
            generic = rt_any.provider.allowed(eff.subject, ot.name.lower(), ot.relation, rt_any.store.keys(t)).keys
            al = rt_any.checker.allow_list(eff, t)
            if al.reach is not None:
                got = {r[ot.primary_key] for r in rt_any.store.select(
                    t, ot.primary_key, allowed=al.reach, visible=[ot.primary_key], types={}, limit=1000)}
            else:
                got = set(al.keys or ())
            assert got == set(generic), (who, t)


def test_query_types_validate_enforce_and_suppress(rt_any):
    r = rt_any.retriever
    out = r.run_query("alice", "revenue_by_filing", {"tag": "Revenues"})
    assert {x["adsh"]: x["value"] for x in out["rows"]} == {"0000320193-26-000001": 1000.0, "0000789019-26-000002": 2000.0}
    walled = r.run_query("walter", "revenue_by_filing", {"tag": "Revenues"})
    assert [x["adsh"] for x in walled["rows"]] == ["0000320193-26-000001"]           # wall applies inside queries
    # whole-population aggregate over < 2 visible rows is suppressed (small-cell suppression)
    assert r.run_query("walter", "average_by_tag", {"tag": "Revenues"})["rows"] == []
    assert r.run_query("alice", "average_by_tag", {"tag": "Revenues"})["rows"][0]["value"] == 1500.0
    # a query over a hidden property is only runnable by those who can see it, and looks nonexistent otherwise
    assert len(r.run_query("rita", "companies_by_risk")["rows"]) == 3
    with pytest.raises(AccessDenied) as e1:
        r.run_query("alice", "companies_by_risk")
    with pytest.raises(AccessDenied) as e2:
        r.run_query("alice", "no_such_query")
    assert str(e1.value) == str(e2.value)
    for bad in [{}, {"tag": 5}, {"tag": "x", "extra": 1}]:
        with pytest.raises(AccessDenied):
            r.run_query("alice", "revenue_by_filing", bad)
    assert "SENTINEL" not in json.dumps(r.run_query("alice", "revenue_by_filing", {"tag": "Revenues"}))


@pytest.mark.parametrize("bad,msg", [
    ({"object": "Nope"}, "unknown object"),
    ({"object": "Fact", "where": [{"property": "zzz", "value": 1}]}, "unknown property"),
    ({"object": "Fact", "where": [{"property": "tag"}]}, "exactly one"),
    ({"object": "Fact", "where": [{"property": "tag", "param": "p"}]}, "undeclared"),
    ({"object": "Fact", "group_by": ["tag"]}, "requires an aggregate"),
    ({"object": "Fact", "aggregate": {"op": "sum", "property": "tag"}}, "numeric"),
    ({"object": "Fact", "aggregate": {"op": "count"}, "min_group_size": 0}, "min_group_size"),
])
def test_invalid_query_types_rejected(bad, msg):
    base = {"objects": {"Fact": {"primary_key": "id", "properties": {"id": {}, "tag": {}, "value": {"type": "number"}}}}}
    with pytest.raises(SchemaError, match=msg):
        parse_schema({**base, "queries": {"q": bad}})


# ---------------- migrations ---------------------------------------------------------------
def schema_with(rt, mutate):
    import yaml
    d = yaml.safe_load((DEMO / "schema.yaml").read_text())
    mutate(d)
    return parse_schema(d)


def test_add_rename_and_widen_with_backfill(rt):
    def mut(d):
        d["objects"]["Filing"]["properties"]["priority"] = {"type": "integer", "default": 3}
        d["objects"]["Filing"]["properties"]["fiscal_year"] = {"type": "string"}   # fy (integer) renamed AND widened
        del d["objects"]["Filing"]["properties"]["fy"]
    new = schema_with(rt, mut)
    m = plan(rt.schema, new, renames={"Filing.fy": "fiscal_year"})
    kinds = [s.kind for s in m.steps]
    assert {"add_property", "rename_property", "change_type"} <= set(kinds) and not m.destructive
    touched = apply(m, rt.schema, new, rt.store)
    f = rt.store.get("Filing", "0000320193-26-000001")
    assert f["priority"] == 3 and f["fiscal_year"] == "2026" and "fy" not in f
    assert touched["add_property"] == 3 and touched["rename_property"] == 3
    assert apply(plan(new, new), new, new, rt.store) == {}                    # idempotent: nothing left to do


def test_lossy_change_is_destructive_and_a_bad_value_rolls_everything_back(rt):
    rt.store.put("Filing", "0000320193-26-000001", {**rt.store.get("Filing", "0000320193-26-000001"), "form": "10-K"})

    def mut(d):
        d["objects"]["Filing"]["properties"]["form"]["type"] = "integer"        # "10-K" is not an integer
        d["objects"]["Filing"]["properties"]["marker"] = {"type": "string", "default": "x"}
    new = schema_with(rt, mut)
    m = plan(rt.schema, new)
    assert m.destructive
    with pytest.raises(MigrationError, match="destructive"):
        apply(m, rt.schema, new, rt.store)
    before = {k: rt.store.get("Filing", k) for k in rt.store.keys("Filing")}
    with pytest.raises(MigrationError, match="is not integral|could not convert|invalid literal"):
        apply(m, rt.schema, new, rt.store, allow_destructive=True)
    assert {k: rt.store.get("Filing", k) for k in rt.store.keys("Filing")} == before    # nothing half-applied
    assert rt.store.get("Filing", "0000320193-26-000001")["form"] == "10-K"


def test_drop_property_and_type_need_explicit_consent(rt):
    def mut(d):
        del d["objects"]["Filing"]["properties"]["internal_notes"]
        del d["objects"]["Concept"]
        d["links"] = {k: v for k, v in d["links"].items() if k != "concept"}
        d["queries"] = {}
    new = schema_with(rt, mut)
    m = plan(rt.schema, new)
    assert {s.kind for s in m.steps if s.destructive} == {"drop_property", "drop_object_type", "drop_link"}
    with pytest.raises(MigrationError):
        apply(m, rt.schema, new, rt.store)
    apply(m, rt.schema, new, rt.store, allow_destructive=True)
    assert rt.store.count("Concept") == 0 and "internal_notes" not in rt.store.get("Filing", "0000320193-26-000001")
    assert not rt.store.neighbours("concept", "0000320193-26-000001|Revenues|20260930|4")


def test_primary_key_change_is_unsupported(rt):
    new = schema_with(rt, lambda d: d["objects"]["Concept"].update(primary_key="tlabel"))
    with pytest.raises(MigrationError):
        plan(rt.schema, new)


def test_coercions():
    assert coerce("12", "integer") == 12 and coerce(2.0, "integer") == 2 and coerce(3, "number") == 3.0
    assert coerce("true", "boolean") is True and coerce(0, "boolean") is False and coerce(None, "integer") is None
    assert coerce("20260930", "date") == "20260930" and coerce(True, "string") == "true"
    for v, t in [("2.5", "integer"), (True, "number"), ("maybe", "boolean"), ("yesterday", "date")]:
        with pytest.raises(ValueError):
            coerce(v, t)


def test_approved_proposal_migrates_data_and_hostile_rename_is_only_a_hint(rt):
    import yaml
    d = yaml.safe_load((DEMO / "schema.yaml").read_text())
    d["objects"]["Filing"]["properties"]["fiscal_year"] = d["objects"]["Filing"]["properties"].pop("fy")
    d["renames"] = {"Filing.fy": "fiscal_year"}
    p = propose_schema_change(MockModel(yaml.safe_dump(d)), rt.schema, "rename fy")
    assert p.renames == {"Filing.fy": "fiscal_year"} and "~ object Filing" in p.diff.render()
    gate = ApprovalGate(rt.checker)
    with pytest.raises(NotApproved):
        gate.apply(p, rt)                                           # unapproved
    gate.approve(p, "sam")
    p.renames = {}                                                   # tamper with the hint after approval
    with pytest.raises(NotApproved, match="modified"):
        gate.apply(p, rt)
    p.renames = {"Filing.fy": "fiscal_year"}
    touched = gate.apply(p, rt)
    assert touched["rename_property"] == 3 and p.status == "applied"
    assert rt.store.get("Filing", "0000320193-26-000001")["fiscal_year"] == 2026
    assert any(e["action"] == "schema_migration" and e["decision"] == "applied" for e in rt.audit.entries)
    assert isinstance(Migration().describe(), str)
