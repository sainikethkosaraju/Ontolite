import pytest

from ontolite.actions import ActionDenied, ActionEngine
from ontolite.audit.verify import verify_entries

ADSH = "0000320193-26-000001"
SECRET_ADSH = "0000999999-26-000003"


def flag(rt, who="alice", adsh=ADSH):
    return rt.actions.propose(who, "flag_for_review", {"adsh": adsh, "reason": "odd"})


def test_permitted_action_end_to_end(rt):
    cs = flag(rt)
    assert cs.handle and len(cs.handle) >= 40 and cs.status == "proposed"
    out = rt.actions.apply("alice", cs.handle)
    assert out.status == "applied"
    f = rt.store.get("Filing", ADSH)
    assert f["review_status"] == "flagged" and f["review_reason"] == "odd"
    assert rt.store.provenance() == [(cs.ref, "alice", "Filing", ADSH)]
    assert verify_entries(rt.audit.entries)[0]


def test_denied_actions(rt):
    with pytest.raises(ActionDenied):  # analyst cannot request signoff (reviewer-only)
        rt.actions.propose("alice", "request_signoff", {"adsh": ADSH})
    with pytest.raises(ActionDenied):  # agent cannot exceed its caller
        rt.actions.propose("agent-alice", "request_signoff", {"adsh": ADSH})
    with pytest.raises(ActionDenied):  # hidden object: indistinguishable from nonexistent
        flag(rt, adsh=SECRET_ADSH)
    with pytest.raises(ActionDenied):
        rt.actions.propose("alice", "no_such_action", {})
    with pytest.raises(ActionDenied):
        rt.actions.propose("alice", "flag_for_review", {"adsh": ADSH})  # missing param
    with pytest.raises(ActionDenied):
        rt.actions.propose("alice", "flag_for_review", {"adsh": ADSH, "reason": 5})
    with pytest.raises(ActionDenied):
        rt.actions.propose("ghost", "flag_for_review", {"adsh": ADSH, "reason": "x"})
    assert rt.store.get("Filing", ADSH).get("review_status") is None


def test_edit_outside_declared_set_rejected(rt):
    a = rt.schema.actions["flag_for_review"]
    from dataclasses import replace
    evil = replace(a, edits=({"type": "Company", "key_param": "adsh",
                              "set": {"name": "pwned"}}, *a.edits))
    rt.schema.actions["flag_for_review"] = evil  # declared edit_set is only Filing
    with pytest.raises(ActionDenied, match="outside the declared edit set"):
        flag(rt)
    assert rt.store.get("Company", "0000320193")["name"] == "EXAMPLE FRUIT CO"


def test_handle_binding_single_use_and_unguessable(rt):
    cs = flag(rt)
    for who in ("rita", "agent-alice"):
        with pytest.raises(ActionDenied, match="invalid or expired"):
            rt.actions.apply(who, cs.handle)
    with pytest.raises(ActionDenied):
        rt.actions.apply("ghost", cs.handle)
    with pytest.raises(ActionDenied, match="invalid or expired"):
        rt.actions.apply("alice", cs.ref)  # the public ref is not a handle
    with pytest.raises(ActionDenied, match="invalid or expired"):
        rt.actions.apply("alice", "A" * 43)
    rt.actions.apply("alice", cs.handle)
    with pytest.raises(ActionDenied, match="invalid or expired"):  # replay
        rt.actions.apply("alice", cs.handle)
    assert len({flag(rt).handle for _ in range(50)}) == 50


def test_handle_expires(rt):
    now = [1000.0]
    eng = ActionEngine(rt.schema, rt.store, rt.checker, rt.audit, clock=lambda: now[0], ttl=60)
    cs = eng.propose("alice", "flag_for_review", {"adsh": ADSH, "reason": "x"})
    now[0] += 61
    with pytest.raises(ActionDenied, match="invalid or expired"):
        eng.apply("alice", cs.handle)
    assert rt.store.get("Filing", ADSH).get("review_status") is None


def test_approval_flow(rt):
    f = flag(rt, "rita")
    rt.actions.apply("rita", f.handle)
    cs = rt.actions.propose("rita", "request_signoff", {"adsh": ADSH})
    with pytest.raises(ActionDenied, match="approval required"):
        rt.actions.apply("rita", cs.handle)
    for who in ("alice", "rita", "agent-rita"):  # no role / self / agent of proposer
        with pytest.raises(ActionDenied):
            rt.actions.approve(who, cs.ref)
    rt.actions.approve("lena", cs.ref)
    with pytest.raises(ActionDenied, match="invalid or expired"):  # approver cannot apply
        rt.actions.apply("lena", cs.handle)
    assert rt.actions.apply("rita", cs.handle).status == "applied"
    assert rt.store.get("Filing", ADSH)["signoff_status"] == "signed_off"
    # precondition: already signed off -> cannot flag again
    with pytest.raises(ActionDenied, match="precondition"):
        flag(rt, "rita")


def test_precondition_blocks_signoff_without_flag(rt):
    with pytest.raises(ActionDenied, match="precondition"):
        rt.actions.propose("rita", "request_signoff", {"adsh": ADSH})


def test_state_change_between_propose_and_apply(rt):
    cs = rt.actions.propose("rita", "flag_for_review", {"adsh": ADSH, "reason": "a"})
    s = rt.store.get("Filing", ADSH); s["signoff_status"] = "signed_off"
    rt.store.put("Filing", ADSH, s)
    with pytest.raises(ActionDenied):
        rt.actions.apply("rita", cs.handle)


def test_atomic_apply_rolls_back(rt, monkeypatch):
    cs = flag(rt)
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(rt.store, "record_provenance", boom)
    with pytest.raises(RuntimeError):
        rt.actions.apply("alice", cs.handle)
    assert rt.store.get("Filing", ADSH).get("review_status") is None
    assert rt.store.provenance() == []


def test_reject(rt):
    cs = flag(rt)
    rt.actions.reject("alice", cs.ref)
    with pytest.raises(ActionDenied):
        rt.actions.apply("alice", cs.handle)
    with pytest.raises(ActionDenied):
        rt.actions.reject("rita", cs.ref)


def test_persisted_across_engines(rt):
    cs = flag(rt)
    eng2 = ActionEngine(rt.schema, rt.store, rt.checker, rt.audit)
    assert eng2.apply("alice", cs.handle).status == "applied"
    assert rt.actions.pending_refs() == []
