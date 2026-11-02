import copy

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from ontolite.permissions.checks import Checker
from ontolite.permissions.rebac import AllowList, InMemoryPermissionStore, PermissionUnavailable
from ontolite.retrieval import AccessDenied

from .conftest import DEMO, build

BASE = yaml.safe_load((DEMO / "principals.yaml").read_text())


def test_agent_never_exceeds_caller(rt):
    c = rt.checker
    alice, agent = c.resolve("alice"), c.resolve("agent-alice")
    assert agent.roles <= alice.roles and agent.subject == "alice"
    assert c.resolve("orphan-agent") is None and c.resolve("ghost") is None
    assert c.resolve("agent-rita").roles == c.resolve("rita").roles   # no own roles: inherits, never more


def test_property_visibility(rt):
    assert "risk_rating" not in rt.checker.visible_properties(rt.checker.resolve("alice"), "Company")
    assert "risk_rating" in rt.checker.visible_properties(rt.checker.resolve("rita"), "Company")


def test_unknown_principal_denied(rt):
    with pytest.raises(AccessDenied):
        rt.retriever.search("ghost", "Company")


def test_compliance_wall_is_an_exclusion_that_inherits_down_the_graph(rt):
    seen = lambda who, t: {r[rt.schema.objects[t].primary_key] for r in rt.retriever.search(who, t, limit=200)}  # noqa: E731
    assert seen("alice", "Company") == {"0000320193", "0000789019"}
    assert seen("walter", "Company") == {"0000320193"}                    # walled from 0000789019
    assert seen("walter", "Filing") == {"0000320193-26-000001"}          # ...and from its filings
    assert all(f.startswith("0000320193") for f in seen("walter", "Fact"))  # ...and its facts
    with pytest.raises(AccessDenied):
        rt.retriever.get("walter", "Company", "0000789019")
    # the wall holds for the agent acting for walter's colleague only through its caller
    assert seen("agent-alice", "Company") == seen("alice", "Company")


def test_revoking_a_tuple_takes_effect_on_the_next_read(rt):
    assert rt.retriever.search("alice", "Company", text="SOFT")
    rt.tuples.write(deletes=[("company:0000789019", "viewer", "user:alice")])
    assert rt.retriever.search("alice", "Company", text="SOFT") == []
    assert rt.retriever.search("alice", "Filing", text="0000789019") == []   # inherited access vanished too


_users = st.text("abcdef", min_size=1, max_size=4)
_objs = st.sampled_from(["company:0000999999", "company:zzz", "group:other", "filing:x"])


@settings(max_examples=40, deadline=None)
@given(extra=_users, rel=st.sampled_from(["viewer", "reviewer", "member", "walled"]), obj=_objs)
def test_unrelated_grants_never_widen_access(extra, rel, obj):
    """Tuples for OTHER users on objects alice has no path to never change what alice can read."""
    d2 = copy.deepcopy(BASE)
    d2["principals"]["x_" + extra] = {"kind": "user", "roles": ["analyst"]}
    d2["tuples"].append([obj, rel, f"user:x_{extra}"])

    def view(data):
        r = build()
        r.tuples.write(adds=[tuple(t) for t in data["tuples"] if tuple(t) not in {tuple(x) for x in BASE["tuples"]}])
        return {t: r.retriever.search("alice", t, limit=200) for t in ("Company", "Filing", "Fact", "Concept")}
    assert view(BASE) == view(d2)


def test_fail_closed_when_the_authz_backend_is_down(rt):
    class Down:
        def __getattr__(self, name):
            raise ConnectionError("authz backend down")
    rt.provider = Down()
    rt._wire()
    for call in (lambda: rt.retriever.search("alice", "Company"),
                 lambda: rt.retriever.get("alice", "Company", "0000320193"),
                 lambda: rt.retriever.query("alice", "Fact", "count"),
                 lambda: rt.retriever.traverse("alice", "Company", "0000320193", "filings"),
                 lambda: rt.retriever.run_query("alice", "revenue_by_filing", {"tag": "Revenues"})):
        with pytest.raises(AccessDenied, match="unavailable"):
            call()


def test_fail_closed_on_truncated_allow_list(rt):
    real = rt.provider

    class Truncating:                       # emulates a remote engine that drops part of a list
        def __getattr__(self, name):
            return getattr(real, name)
        reach = None
        def allowed(self, *a, **k):
            al = real.allowed(*a, **k)
            return AllowList(frozenset(sorted(al.keys)[:-1]), al.expected)
    rt.provider = Truncating()
    rt._wire()
    with pytest.raises(AccessDenied, match="unavailable"):
        rt.retriever.search("alice", "Company")
    with pytest.raises(PermissionUnavailable):
        rt.checker.allow_list(rt.checker.resolve("alice"), "Company")
    assert isinstance(rt.checker, Checker)


def test_evaluation_errors_in_the_engine_deny_rather_than_allow(rt):
    from ontolite.authz import parse_namespaces
    rt.authz.ns = parse_namespaces({"company": {"relations": {
        "banned": "this", "viewer": {"exclusion": {"base": "this", "subtract": {"computed": "banned"}}}}}})
    rt.tuples.write(adds=[("company:0000320193", "viewer", "company:0000320193#viewer"),
                          ("company:0000320193", "banned", "company:0000320193#viewer")])
    with pytest.raises(AccessDenied, match="unavailable"):          # cycle under exclusion -> deny
        rt.retriever.get("alice", "Company", "0000320193")


def test_in_memory_store_loads_yaml_tuples():
    s = InMemoryPermissionStore.from_dict(BASE)
    assert ("company:0000789019", "walled", "user:walter") in s.tuples


def test_checker_edge_cases_all_fail_closed_or_deny(rt):
    from ontolite.permissions.checks import Checker
    c, alice = rt.checker, rt.checker.resolve("alice")
    # unknown type / type without a read grant: empty allow-list, never "everything"
    assert c.allow_list(alice, "Nope") == AllowList(frozenset(), 0)
    assert c.allow_list(rt.checker.resolve("lena"), "Company") == AllowList(frozenset(), 0)   # approver can't read Company
    assert not c.can_read_object(alice, "Nope", "x") and not c.can_read_object(rt.checker.resolve("lena"), "Company", "0000320193")
    assert c.can_read_object(alice, "Concept", "anything")                                      # open type, role granted
    # agent whose delegator is itself an agent, or missing, resolves to nothing
    rt.perms.principals["agent-of-agent"] = type(rt.perms.principals["agent-alice"])("agent-of-agent", "agent", (), "agent-alice")
    rt.perms.principals["agent-of-ghost"] = type(rt.perms.principals["agent-alice"])("agent-of-ghost", "agent", (), "ghost")
    assert c.resolve("agent-of-agent") is None and c.resolve("agent-of-ghost") is None
    # actions: unknown action, no approver roles configured
    assert not c.can_propose(alice, "nope") and not c.can_approve(alice, "flag_for_review")
    # object-level type configured but no backend attached -> unavailable, not open
    bare = Checker(rt.schema, rt.perms, provider=None, data=None)
    with pytest.raises(PermissionUnavailable):
        bare.allow_list(alice, "Company")
    with pytest.raises(PermissionUnavailable):
        bare.can_read_object(alice, "Company", "0000320193")
    assert bare._keys_of_namespace("company") == []
    # a failing directory (roles lookup) denies via PermissionUnavailable
    class BrokenDirectory:
        def principal(self, pid): raise OSError("directory down")
        def roles_grant(self, *a): raise OSError("directory down")
    broken = Checker(rt.schema, BrokenDirectory(), rt.provider, rt.store)
    with pytest.raises(PermissionUnavailable):
        broken.resolve("alice")
    with pytest.raises(PermissionUnavailable):
        broken.can_read_type(alice, "Company")
