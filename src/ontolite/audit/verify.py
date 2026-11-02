"""Audit verification: hash chain (cheap, local) + Merkle checks against pinned signed heads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ontolite.audit.log import GENESIS, entry_hash
from ontolite.audit.merkle import (
    MerkleTree,
    SignedTreeHead,
    verify_consistency,
    verify_head_signature,
)


def verify_entries(entries: list[dict], expected_head: str | None = None) -> tuple[bool, str]:
    """Verify the hash chain. Tail truncation is only detectable with `expected_head` or a pinned
    signed tree head (see `verify_against_head`)."""
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


def _load(path: str | Path) -> list[dict]:
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


def verify_audit(path: str | Path, expected_head: str | None = None) -> tuple[bool, str]:
    try:
        entries = _load(path)
    except (OSError, json.JSONDecodeError) as e:
        return False, f"unreadable audit log: {e}"
    return verify_entries(entries, expected_head)


def verify_against_head(entries: list[dict], pinned: SignedTreeHead, public_key: Any,
                        ) -> tuple[bool, str]:
    """The log is intact AND append-only relative to a signed head pinned earlier: the pinned
    signature is valid, the current log is at least as long, and its first `pinned.size` entries
    still hash to the pinned root (i.e. history was not rewritten or truncated)."""
    ok, msg = verify_entries(entries)
    if not ok:
        return False, msg
    if not verify_head_signature(pinned, public_key):
        return False, "pinned tree head has an invalid signature"
    if len(entries) < pinned.size:
        return False, f"log has {len(entries)} entries but a head was signed at {pinned.size}: truncated"
    tree = MerkleTree()
    for e in entries:
        tree.append(e["hash"].encode())
    if tree.root(pinned.size).hex() != pinned.root:
        return False, "history before the pinned head was rewritten"
    proof = tree.consistency_proof(pinned.size, len(tree))
    if not verify_consistency(pinned.size, len(tree), proof, bytes.fromhex(pinned.root), tree.root()):
        return False, "consistency proof failed"
    return True, f"ok: {len(entries)} entries, append-only since size {pinned.size}"
