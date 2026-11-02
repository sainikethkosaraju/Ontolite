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


def build_server(rt: Ontolite, principal: str) -> MCPServer:
    srv = MCPServer("ontolite", cache_hints={"tools/list": CacheHint(ttl_ms=0, scope="private")})

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
        cs = rt.actions.apply(principal, handle)
        return {"ref": cs.ref, "status": cs.status, "edits": cs.edits}

    @srv.tool()
    @guarded
    def approve_action(ref: str) -> dict[str, Any]:
        """Approve a pending change set by its public ref (requires an approver role)."""
        cs = rt.actions.approve(principal, ref)
        return {"ref": cs.ref, "status": cs.status}

    @srv.tool()
    @guarded
    def get(type: str, key: str) -> dict[str, Any]:
        """Get one object by type and primary key, with only the properties you may see."""
        return rt.retriever.get(principal, type, key)

    @srv.tool()
    @guarded
    def propose_action(action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Stage an action. Returns a secret handle (for apply_action) and a public ref."""
        cs = rt.actions.propose(principal, action, params)
        return {"handle": cs.handle, "ref": cs.ref, "status": cs.status, "edits": cs.edits,
                "expires_at": cs.expires_at}

    @srv.tool()
    @guarded
    def query(type: str, op: str, property: str | None = None,
              filters: dict[str, Any] | None = None) -> dict[str, Any]:
        """Aggregate (count/sum/avg/min/max) over objects you may see, on properties you may see."""
        return rt.retriever.query(principal, type, op, property, filters)

    @srv.tool()
    @guarded
    def search(type: str, text: str = "", filters: dict[str, Any] | None = None,
               limit: int = 20) -> list[dict[str, Any]]:
        """Search objects of a type by visible-property text and equality filters."""
        return rt.retriever.search(principal, type, text, filters, limit)

    @srv.tool()
    @guarded
    def traverse(type: str, key: str, link: str) -> list[dict[str, Any]]:
        """Follow a link (either direction) from an object to the objects you may see."""
        return rt.retriever.traverse(principal, type, key, link)

    return srv
