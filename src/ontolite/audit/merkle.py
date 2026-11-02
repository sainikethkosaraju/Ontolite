"""RFC 6962 / RFC 9162 Merkle tree: root, inclusion proofs, consistency proofs and their
verifiers, plus Ed25519 signed tree heads. An append-only log is exactly one whose later tree heads
are consistent with every earlier one."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

EMPTY = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


class MerkleTree:
    def __init__(self, leaves: list[bytes] | None = None) -> None:
        self.leaves: list[bytes] = list(leaves or [])  # leaf HASHES
        self._memo: dict[tuple[int, int], bytes] = {}

    def append(self, data: bytes) -> int:
        self.leaves.append(leaf_hash(data))
        return len(self.leaves) - 1

    def __len__(self) -> int:
        return len(self.leaves)

    def _mth(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY
        if n == 1:
            return self.leaves[lo]
        key = (lo, hi)
        if key in self._memo:
            return self._memo[key]
        k = _split(n)
        h = node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
        if n & (n - 1) == 0:  # aligned full subtrees never change as the log grows
            self._memo[key] = h
        return h

    def root(self, size: int | None = None) -> bytes:
        size = len(self.leaves) if size is None else size
        if size > len(self.leaves):
            raise ValueError("size exceeds tree")
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = len(self.leaves) if size is None else size
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError("index out of range")

        def path(m: int, lo: int, hi: int) -> list[bytes]:
            n = hi - lo
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, lo, lo + k) + [self._mth(lo + k, hi)]
            return path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]
        return path(index, 0, size)

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        second = len(self.leaves) if second is None else second
        if not 0 <= first <= second <= len(self.leaves):
            raise ValueError("bad sizes")
        if first in (0, second):
            return []

        def sub(m: int, lo: int, hi: int, b: bool) -> list[bytes]:
            n = hi - lo
            if m == n:
                return [] if b else [self._mth(lo, hi)]
            k = _split(n)
            if m <= k:
                return sub(m, lo, lo + k, b) + [self._mth(lo + k, hi)]
            return sub(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]
        return sub(first, 0, second, True)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """`leaf` is the leaf HASH. RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, proof: list[bytes], first_root: bytes,
                       second_root: bytes) -> bool:
    """RFC 9162 section 2.1.4.2: the tree of size `second` extends the tree of size `first`."""
    if first > second or first < 0:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof
    proof = list(proof)
    if first & (first - 1) == 0:
        proof.insert(0, first_root)
    if not proof:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


@dataclass(frozen=True)
class SignedTreeHead:
    size: int
    root: str  # hex
    time: float
    sig: str  # hex Ed25519 over canonical (size, root, time)

    def payload(self) -> bytes:
        return json.dumps({"size": self.size, "root": self.root, "time": self.time},
                          sort_keys=True, separators=(",", ":")).encode()

    def to_json(self) -> str:
        return json.dumps({"size": self.size, "root": self.root, "time": self.time, "sig": self.sig},
                          sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> SignedTreeHead:
        d = json.loads(text)
        return cls(int(d["size"]), str(d["root"]), float(d["time"]), str(d["sig"]))


def sign_head(tree: MerkleTree, private_key: Any, now: float | None = None) -> SignedTreeHead:
    unsigned = SignedTreeHead(len(tree), tree.root().hex(), time.time() if now is None else now, "")
    return SignedTreeHead(unsigned.size, unsigned.root, unsigned.time,
                          private_key.sign(unsigned.payload()).hex())


def verify_head_signature(sth: SignedTreeHead, public_key: Any) -> bool:
    try:
        public_key.verify(bytes.fromhex(sth.sig), SignedTreeHead(sth.size, sth.root, sth.time, "").payload())
        return True
    except Exception:
        return False
