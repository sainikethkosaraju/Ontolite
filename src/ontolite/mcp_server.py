"""MCP server (official SDK v2, `MCPServer`). One server instance serves exactly one principal;
`tools/list` order is deterministic (sorted by name) and cache scope is private because results
depend on who is asking. Errors never reveal whether a hidden object exists."""

from __future__ import annotations

import functools
from typing import Any

from mcp.server.caching import CacheHint
from mcp.server.mcpserver import MCPServer

from ontolite.actions import ActionDenied
from ontolite.retrieval import AccessDenied
from ontolite.runtime import Ontolite


def build_server(rt: Ontolite, principal: str | None = None, *, token_verifier=None,
                 resource_url: str | None = None) -> MCPServer:
    """Static mode: `principal` fixed (stdio). HTTP mode: pass a `token_verifier`; the principal is the
    authenticated token's subject on every call, and an unauthenticated call is refused."""
    kwargs: dict[str, Any] = {}
    if token_verifier is not None:
        from mcp.server.auth.settings import AuthSettings

        from ontolite.http_auth import SCOPE
        url = resource_url or "http://127.0.0.1:8000/mcp"
        kwargs = {"token_verifier": token_verifier,
                  "auth": AuthSettings(issuer_url=url.rsplit("/", 1)[0] or url,  # type: ignore[arg-type]
                                       resource_server_url=url,  # type: ignore[arg-type]
                                       required_scopes=[SCOPE])}
    elif principal is None:
        raise ValueError("give a fixed principal or a token_verifier")
    srv = MCPServer("ontolite", cache_hints={"tools/list": CacheHint(ttl_ms=0, scope="private")}, **kwargs)

    def who() -> str:
        if principal is not None:
            return principal
        from mcp.server.auth.middleware.auth_context import get_access_token
        tok = get_access_token()
        if tok is None or not tok.subject:
            raise AccessDenied("not found or not permitted")   # fail closed: never default to a principal
        return tok.subject

    def guarded(fn):
        @functools.wraps(fn)
        def run(*a, **kw):
            try:
                return fn(*a, **kw)
            except (AccessDenied, ActionDenied) as e:
                raise ValueError(str(e)) from None
        return run

    # Registered in sorted name order so tools/list is deterministic.
    @srv.tool()
    @guarded
    def apply_action(handle: str) -> dict[str, Any]:
        """Apply a previously proposed (and, if required, approved) change set by its handle."""
        cs = rt.actions.apply(who(), handle)
        return {"ref": cs.ref, "status": cs.status, "edits": cs.edits}

    @srv.tool()
    @guarded
    def approve_action(ref: str) -> dict[str, Any]:
        """Approve a pending change set by its public ref (requires an approver role)."""
        cs = rt.actions.approve(who(), ref)
        return {"ref": cs.ref, "status": cs.status}

    @srv.tool()
    @guarded
    def get(type: str, key: str) -> dict[str, Any]:
        """Get one object by type and primary key, with only the properties you may see."""
        return rt.retriever.get(who(), type, key)

    @srv.tool()
    @guarded
    def propose_action(action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Stage an action. Returns a secret handle (for apply_action) and a public ref."""
        cs = rt.actions.propose(who(), action, params)
        return {"handle": cs.handle, "ref": cs.ref, "status": cs.status, "edits": cs.edits,
                "expires_at": cs.expires_at}

    @srv.tool()
    @guarded
    def query(type: str, op: str, property: str | None = None,
              filters: dict[str, Any] | None = None) -> dict[str, Any]:
        """Aggregate (count/sum/avg/min/max) over objects you may see, on properties you may see."""
        return rt.retriever.query(who(), type, op, property, filters)

    @srv.tool()
    @guarded
    def run_query(name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run a declared, typed query (see list_queries). Small groups are suppressed."""
        return rt.retriever.run_query(who(), name, params)

    @srv.tool()
    @guarded
    def search(type: str, text: str = "", filters: dict[str, Any] | None = None,
               limit: int = 20) -> list[dict[str, Any]]:
        """Search objects of a type by visible-property text and equality filters."""
        return rt.retriever.search(who(), type, text, filters, limit)

    @srv.tool()
    @guarded
    def traverse(type: str, key: str, link: str) -> list[dict[str, Any]]:
        """Follow a link (either direction) from an object to the objects you may see."""
        return rt.retriever.traverse(who(), type, key, link)

    return srv
