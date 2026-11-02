import asyncio
import socket
import threading
import time

import httpx
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from ontolite.http_auth import TokenFile
from ontolite.mcp_server import build_server

from .conftest import build


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Running:
    def __init__(self, app, port):
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *a):
        self.server.should_exit = True
        self.thread.join(timeout=5)


def test_token_file_hashes_expires_and_revokes(tmp_path):
    now = [1000.0]
    tf = TokenFile(tmp_path / "tokens.json", clock=lambda: now[0])
    t = tf.issue("alice", ttl=60)
    assert t not in (tmp_path / "tokens.json").read_text()           # only the digest is stored
    assert oct((tmp_path / "tokens.json").stat().st_mode & 0o777) == "0o600"
    assert tf.lookup(t)["principal"] == "alice" and TokenFile(tmp_path / "tokens.json", clock=lambda: now[0]).lookup(t)
    assert tf.lookup("olt_wrong") is None and tf.lookup("") is None
    now[0] += 61
    assert tf.lookup(t) is None
    t2 = tf.issue("rita", ttl=600)
    assert tf.revoke(t2) and tf.lookup(t2) is None and not tf.revoke("nope")


def test_one_http_server_many_principals(tmp_path):
    rt = build("sqlite")
    tf = TokenFile(tmp_path / "t.json")
    tokens = {p: tf.issue(p) for p in ("alice", "walter", "rita")}
    port = free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    srv = build_server(rt, token_verifier=tf, resource_url=url)
    app = srv.streamable_http_app()

    async def as_principal(token):
        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"} if token else {})
        async with Client(streamable_http_client(url, http_client=http)) as c:
            comp = await c.call_tool("search", {"type": "Company"})
            q = await c.call_tool("run_query", {"name": "companies_by_risk"})
            return comp, q

    with Running(app, port):
        # no token / bad token / revoked token: refused at the transport, before any tool runs
        for bad in (None, "olt_forged", tf.issue("alice", ttl=-1)):
            r = httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                           headers={"Authorization": f"Bearer {bad}"} if bad else {})
            assert r.status_code == 401
        res = {p: asyncio.run(as_principal(t)) for p, t in tokens.items()}
    names = {p: sorted(r["name"] for r in c.structured_content["result"]) for p, (c, _) in res.items()}
    assert names["alice"] == ["EXAMPLE FRUIT CO", "EXAMPLE SOFT CORP"]
    assert names["walter"] == ["EXAMPLE FRUIT CO"]                        # compliance wall, same server
    assert len(names["rita"]) == 3
    assert res["alice"][1].is_error and res["walter"][1].is_error         # hidden-property query: refused
    assert not res["rita"][1].is_error
    assert all("SENTINEL" not in str(c) for p, (c, _) in res.items() if p != "rita")
    assert any(e["principal"] == "walter" for e in rt.audit.entries)      # audit attributes calls to the TOKEN's subject
