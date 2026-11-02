import asyncio
import json

import pytest
from mcp import Client

from ontolite.cli import _open, main
from ontolite.mcp_server import build_server

ADSH = "0000320193-26-000001"
TOOLS = ["apply_action", "approve_action", "get", "propose_action", "query", "run_query", "search", "traverse"]


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
    assert main(["audit", "verify", "--dir", d]) == 0  # fresh project verifies
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
    import yaml
    base = yaml.safe_load((tmp_path / "proj" / "schema.yaml").read_text())
    additive = dict(base, objects={**base["objects"], "Note": {"primary_key": "id", "properties": {"id": {}}}})
    new = tmp_path / "new.yaml"
    new.write_text(yaml.safe_dump(additive))
    assert main(["schema", "diff", str(tmp_path / "proj" / "schema.yaml"), str(new)]) == 0
    assert "+ object Note" in capsys.readouterr().out
    assert main(["propose", "--dir", d, "--from-file", str(new), "--approve-as", "alice"]) == 1
    assert main(["propose", "--dir", d, "--from-file", str(new), "--approve-as", "sam"]) == 0
    destructive = tmp_path / "wipe.yaml"
    destructive.write_text("objects: {Note: {primary_key: id, properties: {id: {}}}}")
    assert main(["propose", "--dir", d, "--from-file", str(destructive), "--approve-as", "sam"]) == 1  # refused
    assert main(["propose", "--dir", d, "--from-file", str(destructive), "--approve-as", "sam",
                 "--allow-destructive"]) == 0


def test_cli_authz_audit_transparency_tokens_and_migration(tmp_path, capsys):
    d = str(tmp_path / "p")
    assert main(["init", "--dir", d]) == 0 and main(["ingest", "--dir", d]) == 0
    capsys.readouterr()
    assert main(["authz", "check", "company:0000320193", "viewer", "user:alice", "--dir", d]) == 0
    assert main(["authz", "check", "company:0000999999", "viewer", "user:alice", "--dir", d]) == 1
    assert main(["authz", "who-can", "company:0000789019", "viewer", "--dir", d]) == 0
    out = capsys.readouterr().out
    assert "user:alice" in out and "user:rita" in out and "user:walter" not in out     # walled
    # transparency: sign a head, grow the log, then truncate it
    key = str(tmp_path / "audit.key")
    assert main(["audit", "keygen", "--out", key]) == 0
    rt = _open(d, key=key)
    for _ in range(5):
        rt.retriever.search("alice", "Company")
    heads = str(tmp_path / "heads.jsonl")
    assert main(["audit", "checkpoint", "--dir", d, "--key", key, "--out", heads]) == 0
    _open(d).retriever.search("alice", "Company")
    pub = key.replace(".key", ".pub")
    assert main(["audit", "verify", "--dir", d, "--pinned", heads, "--pubkey", pub]) == 0
    assert main(["audit", "prove", "2", "--dir", d]) == 0
    proof = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    from ontolite.audit import verify_inclusion
    assert verify_inclusion(bytes.fromhex(proof["leaf"]), proof["seq"], proof["size"],
                            [bytes.fromhex(x) for x in proof["proof"]], bytes.fromhex(proof["root"]))
    audit = tmp_path / "p" / "audit.jsonl"
    audit.write_text("\n".join(audit.read_text().splitlines()[:2]) + "\n")             # attacker truncates the tail
    assert main(["audit", "verify", "--dir", d]) == 0                                  # local chain still looks fine...
    assert main(["audit", "verify", "--dir", d, "--pinned", heads, "--pubkey", pub]) == 1   # ...the pinned head exposes it
    # tokens and migration planning
    assert main(["token", "issue", "alice", "--dir", d]) == 0
    tok = capsys.readouterr().out.strip().splitlines()[-1]
    assert tok.startswith("olt_") and main(["token", "revoke", tok, "--dir", d]) == 0
    import yaml
    base = yaml.safe_load((tmp_path / "p" / "schema.yaml").read_text())
    base["objects"]["Filing"]["properties"]["fiscal_year"] = base["objects"]["Filing"]["properties"].pop("fy")
    new = tmp_path / "new.yaml"
    new.write_text(yaml.safe_dump(base))
    assert main(["migrate", "plan", str(tmp_path / "p" / "schema.yaml"), str(new), "--rename", "Filing.fy=fiscal_year"]) == 0
    assert "rename_property Filing.fiscal_year" in capsys.readouterr().out
    assert main(["migrate", "plan", str(tmp_path / "p" / "schema.yaml"), str(new)]) == 1     # w/o rename: drop+add = destructive
