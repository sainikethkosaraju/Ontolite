import asyncio
import json

import pytest
from mcp import Client

from ontolite.cli import main
from ontolite.mcp_server import build_server

ADSH = "0000320193-26-000001"
TOOLS = ["apply_action", "approve_action", "get", "propose_action", "query", "search", "traverse"]


def run(coro):
    return asyncio.run(coro)


def payload(res):
    return res.structured_content.get("result", res.structured_content)


@pytest.mark.parametrize("mode", ["auto", "legacy"])  # current-revision and earlier-revision clients
def test_e2e(rt, mode):
    async def go():
        async with Client(build_server(rt, "alice"), mode=mode) as ca, \
                Client(build_server(rt, "rita"), mode=mode) as cr, \
                Client(build_server(rt, "lena"), mode=mode) as cl:
            tools = await ca.list_tools()
            assert [t.name for t in tools.tools] == TOOLS  # deterministic order
            if mode == "auto":
                assert str(getattr(tools, "cache_scope", "private")) == "private"
            # same question, different answers
            a = payload(await ca.call_tool("search", {"type": "Company"}))
            r = payload(await cr.call_tool("search", {"type": "Company"}))
            assert len(a) == 2 and len(r) == 3
            assert "SENTINEL" not in json.dumps(a) and "SENTINEL" in json.dumps(r)
            hidden = await ca.call_tool("get", {"type": "Company", "key": "0000999999"})
            assert hidden.is_error and "SECRETCO" not in json.dumps(hidden.model_dump(), default=str)
            # staged action: analyst flags
            p = payload(await ca.call_tool("propose_action", {
                "action": "flag_for_review", "params": {"adsh": ADSH, "reason": "mcp"}}))
            applied = payload(await ca.call_tool("apply_action", {"handle": p["handle"]}))
            assert applied["status"] == "applied"
            replay = await ca.call_tool("apply_action", {"handle": p["handle"]})
            assert replay.is_error
            # approval flow across three principals
            s = payload(await cr.call_tool("propose_action", {
                "action": "request_signoff", "params": {"adsh": ADSH}}))
            early = await cr.call_tool("apply_action", {"handle": s["handle"]})
            assert early.is_error
            assert (await ca.call_tool("approve_action", {"ref": s["ref"]})).is_error
            await cl.call_tool("approve_action", {"ref": s["ref"]})
            done = payload(await cr.call_tool("apply_action", {"handle": s["handle"]}))
            assert done["status"] == "applied"
    run(go())


def test_cli_flow(tmp_path, capsys):
    d = str(tmp_path / "proj")
    assert main(["init", "--dir", d]) == 0
    assert main(["ingest", "--dir", d]) == 0
    assert '"sub.txt->Company": 3' in capsys.readouterr().out
    from ontolite.cli import _open
    rt = _open(d)
    cs = rt.actions.propose("alice", "flag_for_review", {"adsh": ADSH, "reason": "cli"})
    assert main(["apply", "--dir", d, "--principal", "alice", cs.handle]) == 0
    assert main(["audit", "verify", "--dir", d]) == 0
    audit = tmp_path / "proj" / "audit.jsonl"
    lines = audit.read_text().splitlines()
    audit.write_text("\n".join(lines).replace('"alice"', '"mallory"', 1) + "\n")
    assert main(["audit", "verify", "--dir", d]) == 1
    new = tmp_path / "new.yaml"
    new.write_text("objects: {Note: {primary_key: id, properties: {id: {}}}}")
    assert main(["schema", "diff", str(tmp_path / "proj" / "schema.yaml"), str(new)]) == 0
    assert "+ object Note" in capsys.readouterr().out
    assert main(["propose", "--dir", d, "--from-file", str(new), "--approve-as", "alice"]) == 1
    assert main(["propose", "--dir", d, "--from-file", str(new), "--approve-as", "sam"]) == 0
