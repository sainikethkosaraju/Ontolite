import copy

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from ontolite.permissions.checks import Checker
from ontolite.permissions.rebac import InMemoryPermissionStore, PermissionUnavailable
from ontolite.retrieval import AccessDenied

from .conftest import DEMO

BASE = yaml.safe_load((DEMO / "principals.yaml").read_text())


def test_agent_never_exceeds_caller(rt):
    c = rt.checker
    alice, agent = c.resolve("alice"), c.resolve("agent-alice")
    assert agent.roles <= alice.roles and agent.subject == "alice"
    assert c.resolve("orphan-agent") is None and c.resolve("ghost") is None
    # agent-rita lists no roles of its own: inherits rita's, no more
    assert c.resolve("agent-rita").roles == c.resolve("rita").roles


def test_property_visibility(rt):
    assert "risk_rating" not in rt.checker.visible_properties(rt.checker.resolve("alice"), "Company")
    assert "risk_rating" in rt.checker.visible_properties(rt.checker.resolve("rita"), "Company")


def test_unknown_principal_denied(rt):
    with pytest.raises(AccessDenied):
        rt.retriever.search("ghost", "Company")


_roles = st.sampled_from(["analyst", "reviewer", "approver", "schema_admin", "nobody"])
_types = st.sampled_from(["Company", "Filing", "Fact", "Concept"])


@settings(max_examples=60, deadline=None)
@given(extra_principal=st.text("abcdef", min_size=1, max_size=5), role=_roles, t=_types,
       key=st.text("0123456789", min_size=3, max_size=10))
def test_unrelated_grants_never_widen_access(extra_principal, role, t, key):
    """Adding grants/tuples for OTHER principals or unrelated objects never changes alice's view."""
    from ontolite.ingest.sec_loader import load_sec
    from ontolite.runtime import Ontolite
    d2 = copy.deepcopy(BASE)
    pid = "x_" + extra_principal
    d2["principals"][pid] = {"kind": "user", "roles": [role]}
    d2["relationships"].append([pid, "viewer", f"{t}:{key}"])
    d2["roles"].setdefault("extra_role", {"grants": {t: ["read"]}})

    def view(data):
        sc, st_ = _base()
        r = Ontolite(sc, st_, InMemoryPermissionStore.from_dict(data))
        load_sec(r.schema, r.store, DEMO / "sample", DEMO / "mappings.yaml")
        return {ty: [x for x in r.retriever.search("alice", ty, limit=200)]
                for ty in ("Company", "Filing", "Fact", "Concept")}
    assert view(BASE) == view(d2)


def _base():
    from ontolite.schema import load_schema
    from ontolite.store import SQLiteStore
    return load_schema(DEMO / "schema.yaml"), SQLiteStore()


def test_fail_closed_when_permission_store_down(rt):
    class Down:
        def __getattr__(self, name):
            raise ConnectionError("permission store down")
    rt.perms = Down()
    rt._wire()
    for call in (lambda: rt.retriever.search("alice", "Company"),
                 lambda: rt.retriever.get("alice", "Company", "0000320193"),
                 lambda: rt.retriever.query("alice", "Fact", "count"),
                 lambda: rt.retriever.traverse("alice", "Company", "0000320193", "filings")):
        with pytest.raises(AccessDenied, match="unavailable"):
            call()


def test_fail_closed_on_truncated_allow_list(rt):
    real = rt.perms
    class Truncating:
        def __getattr__(self, name):
            return getattr(real, name)
        def allow_list(self, subject, type_):
            al = real.allow_list(subject, type_)
            from ontolite.permissions.rebac import AllowList
            return AllowList(frozenset(sorted(al.keys)[:-1]), al.expected)  # one key lost
    rt.perms = Truncating()
    rt._wire()
    with pytest.raises(AccessDenied, match="unavailable"):
        rt.retriever.search("alice", "Company")
    with pytest.raises(PermissionUnavailable):
        rt.checker.allow_list(rt.checker.resolve("alice"), "Company")
    assert isinstance(rt.checker, Checker)
