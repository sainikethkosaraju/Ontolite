import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from ontolite.authz import (
    Authz,
    AuthzError,
    CycleUnderExclusion,
    DepthExceeded,
    TupleStore,
    parse_namespaces,
)
from ontolite.authz.model import AuthzConfigError
from ontolite.authz.tuples import TupleError

from .oracle import materialise

DOCS = parse_namespaces({
    "group": {"relations": {"member": "this"}},
    "folder": {"relations": {"parent": "this", "owner": "this", "banned": "this",
                             "viewer": {"union": ["this", {"computed": "owner"}, {"ttu": ["parent", "viewer"]}]}}},
    "doc": {"relations": {"parent": "this", "owner": "this", "banned": "this",
                          "can_view": {"exclusion": {"base": {"union": [{"computed": "owner"}, {"ttu": ["parent", "viewer"]}, "this"]},
                                                     "subtract": {"computed": "banned"}}}}},
})


def mk(tuples=(), ns=DOCS, **kw):
    ts = TupleStore()
    ts.write(adds=tuples)
    return Authz(ns, ts, **kw), ts


def test_classic_google_drive_example():
    a, ts = mk([("folder:eng", "owner", "group:eng#member"), ("group:eng", "member", "user:alice"),
                ("folder:specs", "parent", "folder:eng"), ("doc:d1", "parent", "folder:specs")])
    assert a.check("doc:d1", "can_view", "user:alice")          # via doc -> specs -> eng -> owner -> group
    assert not a.check("doc:d1", "can_view", "user:bob")
    ts.write(adds=[("doc:d1", "banned", "user:alice")])
    assert not a.check("doc:d1", "can_view", "user:alice")      # exclusion wins immediately
    ts.write(deletes=[("doc:d1", "banned", "user:alice")])
    assert a.check("doc:d1", "can_view", "user:alice")
    assert a.who_can("doc:d1", "can_view") == {"user:alice"}


def test_revocation_is_immediate_and_snapshots_are_consistent():
    a, ts = mk([("doc:d", "owner", "user:alice")])
    r1 = ts.revision
    assert a.check("doc:d", "can_view", "user:alice")
    r2 = ts.write(deletes=[("doc:d", "owner", "user:alice")])
    assert not a.check("doc:d", "can_view", "user:alice")                  # no stale cache
    assert a.check("doc:d", "can_view", "user:alice", at=r1)               # snapshot read of the past
    assert not a.check("doc:d", "can_view", "user:alice", at=r2)
    assert a.cache_hits >= 0


def test_wildcard_and_unknown_things_grant_nothing():
    a, _ = mk([("doc:d", "owner", "user:*")])
    assert a.check("doc:d", "can_view", "user:anyone")
    assert not a.check("doc:d", "can_view", "service:bot")                 # wildcard is per subject type
    assert not a.check("nope:1", "viewer", "user:alice")
    assert not a.check("doc:d", "no_such_relation", "user:alice")


def test_group_nesting_cycle_is_harmless_for_monotone_rewrites():
    a, _ = mk([("group:a", "member", "group:b#member"), ("group:b", "member", "group:a#member"),
               ("group:b", "member", "user:carol"), ("doc:d", "owner", "group:a#member")])
    assert a.check("doc:d", "can_view", "user:carol") and not a.check("doc:d", "can_view", "user:dave")


def test_cycle_under_exclusion_and_depth_fail_closed():
    ns = parse_namespaces({"doc": {"relations": {
        "banned": "this", "viewer": {"exclusion": {"base": "this", "subtract": {"computed": "banned"}}}}}})
    a, _ = mk([("doc:d", "viewer", "doc:d#viewer"), ("doc:d", "banned", "doc:d#viewer")], ns=ns)
    with pytest.raises(CycleUnderExclusion):
        a.check("doc:d", "viewer", "user:x")
    chain = [("group:g0", "member", "user:u")] + [(f"group:g{i + 1}", "member", f"group:g{i}#member")
                                                 for i in range(40)]
    a2, _ = mk(chain, max_depth=10)
    with pytest.raises(DepthExceeded):
        a2.check("group:g40", "member", "user:u")


def test_link_backed_tupleset_inherits_along_data_links():
    ns = parse_namespaces({"company": {"relations": {"viewer": "this"}},
                           "filing": {"relations": {"company": {"link": {"name": "filings", "inverse": True, "target": "company"}},
                                                    "viewer": {"ttu": ["company", "viewer"]}}}})

    class Links:
        v = 0
        data = {("filing", "f1", "filings", True): ["c1"]}
        def related(self, t, i, link, inv): return self.data.get((t, i, link, inv), [])
        def version(self): return self.v
    links = Links()
    ts = TupleStore(); ts.write(adds=[("company:c1", "viewer", "user:alice")])
    a = Authz(ns, ts, links)
    assert a.check("filing:f1", "viewer", "user:alice") and not a.check("filing:f2", "viewer", "user:alice")
    links.data[("filing", "f2", "filings", True)] = ["c1"]; links.v += 1       # data changed -> cache key changes
    assert a.check("filing:f2", "viewer", "user:alice")
    assert a.list_objects("filing", "viewer", "user:alice", ["f1", "f2", "f3"]) == {"f1", "f2"}
    with pytest.raises(AuthzError):
        Authz(ns, ts, None).check("filing:f1", "viewer", "user:alice")      # link without provider: error, not allow


@pytest.mark.parametrize("bad", [
    {"x": {"relations": {"r": {"computed": "missing"}}}},
    {"x": {"relations": {"r": {"ttu": ["only_one"]}}}},
    {"x": {"relations": {"r": {"union": []}}}},
    {"x": {"relations": {"r": {"bogus": 1}}}},
    {"x": {"relations": {"r": "that"}}},
    {"x": {"relations": {"r": {"exclusion": {"base": "this"}}}}},
])
def test_invalid_namespace_config_rejected(bad):
    with pytest.raises(AuthzConfigError):
        parse_namespaces(bad)


def test_malformed_tuples_rejected():
    ts = TupleStore()
    for bad in [("nocolon", "r", "user:a"), ("doc:1", "r r", "user:a"), ("doc:1", "r", "user:a#"),
                ("doc:1#x", "r", "user:a"), ("doc:1", "r", "")]:
        with pytest.raises(TupleError):
            ts.write(adds=[bad])
    assert ts.revision == 0


# ---------------- differential testing against the independent oracle --------------------------
LEAF = ["this"]


def rewrite_strategy(simple_rels, recursive_ok):
    """Random rewrite. Exclusion operands are cycle-free leaves (this / computed of this-only
    relations); recursion (ttu) appears only in monotone positions."""
    leaf = st.sampled_from(LEAF + [{"computed": r} for r in simple_rels])
    mono = [leaf] + ([st.just({"ttu": ["parent", "viewer"]})] if recursive_ok else [])
    base = st.one_of(*mono)
    return st.recursive(
        base, lambda c: st.one_of(
            st.lists(c, min_size=1, max_size=3).map(lambda xs: {"union": xs}),
            st.lists(c, min_size=2, max_size=3).map(lambda xs: {"intersection": xs}),
            st.tuples(leaf, leaf).map(lambda t: {"exclusion": {"base": t[0], "subtract": t[1]}})),
        max_leaves=6)


@st.composite
def worlds(draw):
    simple = ["owner", "banned"]
    folder_viewer = draw(rewrite_strategy(simple, True))
    doc_viewer = draw(rewrite_strategy(simple, True))
    ns = parse_namespaces({
        "group": {"relations": {"member": "this"}},
        "folder": {"relations": {"parent": "this", "owner": "this", "banned": "this", "viewer": folder_viewer}},
        "doc": {"relations": {"parent": "this", "owner": "this", "banned": "this", "viewer": doc_viewer}},
    })
    users = [f"user:u{i}" for i in range(3)]
    groups = [f"group:g{i}" for i in range(3)]
    folders = [f"folder:f{i}" for i in range(3)]
    docs = [f"doc:d{i}" for i in range(2)]
    subj = st.sampled_from(users + [f"{g}#member" for g in groups] + ["user:*"])
    tuples = set()
    for _ in range(draw(st.integers(0, 14))):
        kind = draw(st.sampled_from(["g", "fo", "fb", "fp", "do", "db", "dp", "fv", "dv"]))
        if kind == "g":
            tuples.add((draw(st.sampled_from(groups)), "member", draw(st.sampled_from(users + [f"{g}#member" for g in groups]))))
        elif kind in {"fo", "fb", "fv"}:
            tuples.add((draw(st.sampled_from(folders)), {"fo": "owner", "fb": "banned", "fv": "viewer"}[kind], draw(subj)))
        elif kind == "fp":
            tuples.add((draw(st.sampled_from(folders)), "parent", draw(st.sampled_from(folders))))
        elif kind in {"do", "db", "dv"}:
            tuples.add((draw(st.sampled_from(docs)), {"do": "owner", "db": "banned", "dv": "viewer"}[kind], draw(subj)))
        else:
            tuples.add((draw(st.sampled_from(docs)), "parent", draw(st.sampled_from(folders))))
    # `this` on viewer is only meaningful when viewer tuples exist; fine either way
    return ns, sorted(tuples), users


@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(worlds())
def test_engine_equals_bottom_up_oracle(world):
    ns, tuples, users = world
    ts = TupleStore(); ts.write(adds=tuples)
    a = Authz(ns, ts)
    S = materialise(ns, ts.all_live(ts.revision), set(users))
    for (obj, rel), expected in S.items():
        for u in users:
            assert a.check(obj, rel, u) == (u in expected), (obj, rel, u, tuples, ns)


class AuthzMachine(RuleBasedStateMachine):
    """Interleave writes and checks: the revision-keyed cache must never serve stale answers."""

    def __init__(self):
        super().__init__()
        self.ts = TupleStore()
        self.a = Authz(DOCS, self.ts)
        self.users = {"user:a", "user:b"}

    objs = ["folder:f1", "folder:f2", "doc:d1"]

    @rule(o=st.sampled_from(["folder:f1", "folder:f2"]), r=st.sampled_from(["owner", "banned"]),
          u=st.sampled_from(["user:a", "user:b"]))
    def add_folder(self, o, r, u): self.ts.write(adds=[(o, r, u)])

    @rule(o=st.sampled_from(["doc:d1"]), r=st.sampled_from(["owner", "banned"]), u=st.sampled_from(["user:a", "user:b"]))
    def add_doc(self, o, r, u): self.ts.write(adds=[(o, r, u)])

    @rule(p=st.sampled_from(["folder:f1", "folder:f2"]))
    def link_doc(self, p): self.ts.write(adds=[("doc:d1", "parent", p)])

    @rule()
    def link_folders(self): self.ts.write(adds=[("folder:f1", "parent", "folder:f2")])

    @rule(i=st.integers(0, 50))
    def revoke_something(self, i):
        live = self.ts.all_live(self.ts.revision)
        if live:
            self.ts.write(deletes=[live[i % len(live)]])

    @invariant()
    def matches_oracle(self):
        S = materialise(DOCS, self.ts.all_live(self.ts.revision), self.users | self.ts.users(self.ts.revision),
                        objects_extra=["doc:d1"])
        for (obj, rel), exp in S.items():
            for u in self.users:
                assert self.a.check(obj, rel, u) == (u in exp)


TestAuthzMachine = AuthzMachine.TestCase
TestAuthzMachine.settings = settings(max_examples=60, stateful_step_count=25, deadline=None)
