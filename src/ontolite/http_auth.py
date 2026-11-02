"""Bearer-token authentication for the HTTP MCP transport.

Tokens are random 256-bit secrets issued per principal. Only SHA-256 digests are stored (a leaked
token file cannot be replayed); verification is constant-time; tokens expire and can be revoked.
The verified token's subject IS the principal for every tool call, so one server instance serves
many principals and a client can never choose its own identity."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

from mcp.server.auth.provider import AccessToken

SCOPE = "ontolite"


class TokenFile:
    def __init__(self, path: str | Path | None = None, clock=time.time) -> None:
        self.path = Path(path) if path else None
        self.clock = clock
        self.records: dict[str, dict] = {}  # sha256(token) -> {principal, exp, revoked}
        if self.path and self.path.exists():
            self.records = json.loads(self.path.read_text() or "{}")

    def _save(self) -> None:
        if self.path:
            self.path.write_text(json.dumps(self.records, indent=1, sort_keys=True))
            self.path.chmod(0o600)

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def issue(self, principal: str, ttl: float = 3600.0) -> str:
        token = "olt_" + secrets.token_urlsafe(32)
        self.records[self._digest(token)] = {"principal": principal, "exp": self.clock() + ttl, "revoked": False}
        self._save()
        return token

    def revoke(self, token: str) -> bool:
        r = self.records.get(self._digest(token))
        if r:
            r["revoked"] = True
            self._save()
        return bool(r)

    def lookup(self, token: str) -> dict | None:
        d = self._digest(token)
        found = None
        for stored, rec in self.records.items():  # constant-time over the whole table, no early exit
            if hmac.compare_digest(stored, d):
                found = rec
        if found is None or found["revoked"] or self.clock() >= found["exp"]:
            return None
        return found

    async def verify_token(self, token: str) -> AccessToken | None:
        rec = self.lookup(token)
        if rec is None:
            return None
        return AccessToken(token=token, client_id=rec["principal"], subject=rec["principal"],
                           scopes=[SCOPE], expires_at=int(rec["exp"]))
