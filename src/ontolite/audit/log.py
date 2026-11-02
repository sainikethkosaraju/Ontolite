"""Append-only, hash-chained audit log (JSONL). Each entry commits to the previous entry's hash."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self.entries = [json.loads(x) for x in self.path.read_text().splitlines() if x.strip()]

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
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
            return e
