from __future__ import annotations

import json
from pathlib import Path

from ontolite.audit.log import GENESIS, entry_hash


def verify_entries(entries: list[dict], expected_head: str | None = None) -> tuple[bool, str]:
    """Verify the chain. Tail truncation is only detectable if the caller pins `expected_head`
    (the last known entry hash), e.g. recorded elsewhere; see docs/threat-model.md."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return False, f"entry {i}: sequence broken (deleted or reordered entry)"
        if e.get("prev") != prev:
            return False, f"entry {i}: previous-hash mismatch"
        if entry_hash(e) != e.get("hash"):
            return False, f"entry {i}: content hash mismatch (edited)"
        prev = e["hash"]
    if expected_head is not None and prev != expected_head:
        return False, "head hash mismatch (log truncated or replaced)"
    return True, f"ok: {len(entries)} entries"


def verify_audit(path: str | Path, expected_head: str | None = None) -> tuple[bool, str]:
    try:
        entries = [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable audit log: {e}"
    return verify_entries(entries, expected_head)
