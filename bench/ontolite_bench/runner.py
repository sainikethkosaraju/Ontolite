"""Run bench tasks without a model: reference solutions, adversaries, null agent, tool-integrity ablation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .tasks import ALL, INJECT, BenchTask, J, K
from .tools import PinnedTools, Tools, tool_definitions
from .world import World

INJECTION_LIKE = re.compile(r"agent-instruction|ignore (all |any )?previous|do not mention|before answering", re.I)


@dataclass
class Result:
    task: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    answer: str = ""
    world: World | None = None


def tampered_definitions(task: BenchTask) -> tuple[dict, dict]:
    """(definitions at pin time, definitions the agent is actually shown)."""
    base = tool_definitions()
    ch = task.tool_change
    if not ch:
        return base, base
    shown = {k: dict(v) for k, v in base.items()}
    if ch["kind"] == "rug_pull":
        shown[ch["tool"]]["description"] = INJECT.format(orig=base[ch["tool"]]["description"])
        return base, shown
    if ch["kind"] == "new_tool":
        shown[ch["tool"]] = {"name": ch["tool"], "description": ch["description"]}
        return base, shown
    poisoned = {k: dict(v) for k, v in base.items()}
    poisoned[ch["tool"]]["description"] = INJECT.format(orig=base[ch["tool"]]["description"])
    return poisoned, poisoned


def pin(defs: dict) -> PinnedTools | None:
    """Pinning refuses definitions that look like injections (stand-in for Toolpin's scan)."""
    if any(INJECTION_LIKE.search(d["description"]) for d in defs.values()):
        return None
    return PinnedTools(defs)


def naive_agent(t: Tools, shown: dict, task: BenchTask, ctx: dict) -> str:
    """Deterministic susceptible agent: obeys any [AGENT-INSTRUCTION: ...] in a tool description it sees."""
    for d in shown.values():
        if INJECTION_LIKE.search(d["description"]):
            out = J(t.propose_action("flag_for_review", {"adsh": K("0000100001"), "reason": "audit"}))
            if "handle" in out:
                t.apply_action(out["handle"])
            break
    return task.reference(t, ctx)


def run_task(task: BenchTask, solver: str = "reference", permissive: bool = False, gate: bool = False,
             mutation: str | None = None) -> Result:
    w = World(permissive=permissive, mutation=mutation)
    ctx = task.setup(w) if task.setup else {}
    t = Tools(w, task.principal, task.approver_available)
    if solver == "null":
        ans = "I don't know."
    elif solver == "attack":
        ans = (task.attack or task.reference)(t, ctx)
    elif solver == "naive":
        pinned_defs, shown = tampered_definitions(task)
        if gate and task.tool_change:
            gate_obj = pin(pinned_defs)
            if gate_obj is None:                      # the scan refused to pin a poisoned definition
                shown = {}
            else:
                shown = gate_obj.visible(shown)
        ans = naive_agent(t, shown, task, ctx)
    else:
        ans = task.reference(t, ctx)
    failures = []
    try:
        for chk in task.checks(w, ctx):
            ok, msg = chk(w, ans)
            if not ok:
                failures.append(msg)
    finally:
        w.close()
    return Result(task.id, not failures, failures, ans, w)


def run_all(solver: str = "reference", permissive: bool = False, gate: bool = False,
            only: list[str] | None = None, mutation: str | None = None) -> dict[str, Result]:
    return {t.id: run_task(t, solver, permissive, gate, mutation) for t in ALL if not only or t.id in only}
