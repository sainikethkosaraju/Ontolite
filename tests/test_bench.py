import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))

from ontolite_bench.runner import run_all  # noqa: E402
from ontolite_bench.tasks import ALL, FAMILIES  # noqa: E402

DENIED_AND_LEAK = {t.id for t in ALL if t.attack}


def test_forty_tasks_in_the_blueprint_families():
    assert len(ALL) == 40
    assert {f: sum(t.family == f for t in ALL) for f in FAMILIES} == FAMILIES


def test_every_reference_solution_passes_every_grader_in_a_fresh_store():
    res = run_all("reference")
    assert [k for k, v in res.items() if not v.passed] == []
    assert all(v.world.rt.audit.entries is not None for v in res.values())


def test_graders_are_not_vacuous_null_agent_fails_everything_that_needs_work():
    res = run_all("null")
    passed = {k for k, v in res.items() if v.passed}
    assert passed == {t.id for t in ALL if t.family == "leakage"}           # doing nothing is only safe, never correct
    assert not passed & {t.id for t in ALL if t.needs_work}


def test_adversaries_are_contained_by_governance():
    res = run_all("attack")
    assert [k for k, v in res.items() if k in DENIED_AND_LEAK and not v.passed] == []


@pytest.mark.parametrize("mutation", ["permissive", "no_handle_binding", "no_preconditions"])
def test_mutation_testing_each_broken_control_is_caught_by_the_tasks_that_guard_it(mutation):
    """Break ONE control on purpose; every task designed to exercise it must then FAIL its graders,
    and the intact system must pass them. This proves the graders can see real breaches."""
    guarded = [t.id for t in ALL if mutation in t.guards]
    assert guarded, mutation
    intact = run_all("attack", only=guarded)
    assert [k for k, v in intact.items() if not v.passed] == []
    broken = run_all("attack", only=guarded, mutation=mutation)
    undetected = [k for k, v in broken.items() if v.passed]
    assert undetected == [], f"graders cannot see a broken {mutation}: {undetected}"


def test_all_fourteen_breach_tasks_are_covered_by_some_mutant():
    assert {t.id for t in ALL if t.attack} == {t.id for t in ALL if t.guards}


def test_tool_integrity_ablation_attack_success_without_and_with_a_gate():
    ids = [t.id for t in ALL if t.family == "tool_integrity"]
    assert sorted(k for k, v in run_all("naive", only=ids).items() if not v.passed) == sorted(ids)   # 4/4 hijacked
    assert [k for k, v in run_all("naive", gate=True, only=ids).items() if not v.passed] == []        # 0/4 with a gate
    assert [k for k, v in run_all("naive").items() if not v.passed and k not in ids] == []


def test_fresh_world_per_trial_no_state_leaks_between_runs():
    a = run_all("reference", only=["action-01"])["action-01"].world
    b = run_all("reference", only=["lookup-01"])["lookup-01"].world
    assert a.truth("Filing", "0000100001-26-000001").get("review_status") == "flagged"
    assert b.truth("Filing", "0000100001-26-000001").get("review_status") is None


def test_runs_inside_inspect_and_inspect_logs_score_40_of_40(tmp_path):
    pytest.importorskip("inspect_ai")
    sys.path.insert(0, str(Path(__file__).parent))
    import conftest  # noqa: F401  (offline tokenizer patch)
    from inspect_ai import eval as inspect_eval
    from ontolite_bench.inspect_tasks import ontolite_bench
    log = inspect_eval(ontolite_bench(solver="reference"), model="mockllm/model", log_dir=str(tmp_path),
                       display="none", epochs=2)[0]
    assert log.status == "success" and len(log.samples) == 80
    assert all(next(iter(s.scores.values())).value == "C" for s in log.samples)
    bad = inspect_eval(ontolite_bench(solver="agent"), model="mockllm/model", log_dir=str(tmp_path / "agent"),
                       display="none")[0]            # mock model never uses tools -> most tasks must FAIL
    assert not any(s.error for s in bad.samples)
    scores = [next(iter(s.scores.values())).value for s in bad.samples]
    assert scores.count("C") < 15
