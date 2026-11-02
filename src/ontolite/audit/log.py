"""Append-only, hash-chained audit log (JSONL). Each entry commits to the previous entry's hash."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from ontolite.audit.merkle import MerkleTree, SignedTreeHead, sign_head

GENESIS = "0" * 64


def digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None, signing_key: Any = None) -> None:
        self.path = Path(path) if path else None
        self.key = signing_key  # Ed25519PrivateKey used to sign tree heads (optional)
        self.entries: list[dict[str, Any]] = []
        self.tree = MerkleTree()
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self.entries = [json.loads(x) for x in self.path.read_text().splitlines() if x.strip()]
            for e in self.entries:
                self.tree.append(e["hash"].encode())

    def append(self, principal: str, action: str, decision: str, params: Any = None,
               before: Any = None, after: Any = None) -> dict[str, Any]:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            e: dict[str, Any] = {
                "seq": len(self.entries), "time": time.time(), "principal": principal,
                "action": action, "params_digest": digest(params), "decision": decision,
                "before_digest": digest(before), "after_digest": digest(after), "prev": prev,
            }
            e["hash"] = entry_hash(e)
            self.entries.append(e)
            self.tree.append(e["hash"].encode())
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
            return e

    # ---- transparency-log features -------------------------------------------------
    def checkpoint(self, path: str | Path | None = None) -> SignedTreeHead:
        """Sign the current tree head; optionally append it to a checkpoint file. Publish or pin
        checkpoints OUTSIDE the machine that holds the log: that is what makes truncation and
        rewrites detectable."""
        if self.key is None:
            raise RuntimeError("no signing key configured")
        sth = sign_head(self.tree, self.key)
        if path:
            with Path(path).open("a") as f:
                f.write(sth.to_json() + "\n")
        return sth
