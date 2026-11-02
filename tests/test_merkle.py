import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from ontolite.audit import (
    AuditLog,
    MerkleTree,
    verify_against_head,
    verify_consistency,
    verify_inclusion,
)
from ontolite.audit.merkle import leaf_hash, sign_head, verify_head_signature

# Certificate Transparency reference leaves/roots (RFC 6962 test data, from the CT reference implementations)
LEAVES = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
          b"\x50\x51\x52\x53\x54\x55\x56\x57", bytes(range(0x60, 0x70))]
ROOTS = {
    1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}


def tree_of(n):
    t = MerkleTree()
    for d in LEAVES[:n]:
        t.append(d)
    return t


def test_empty_and_known_roots_match_the_ct_reference_vectors():
    assert MerkleTree().root() == hashlib.sha256(b"").digest()
    for n, hexroot in ROOTS.items():
        assert tree_of(n).root().hex() == hexroot, n


@pytest.mark.parametrize("size", range(1, 40))
def test_every_inclusion_proof_verifies_and_rejects_tampering(size):
    t = MerkleTree()
    for i in range(size):
        t.append(f"entry-{i}".encode())
    root = t.root()
    for i in range(size):
        proof = t.inclusion_proof(i)
        assert verify_inclusion(t.leaves[i], i, size, proof, root)
        assert not verify_inclusion(leaf_hash(b"forged"), i, size, proof, root)
        if size > 1:
            assert not verify_inclusion(t.leaves[i], (i + 1) % size, size, proof, root) or size == 1
        if proof:
            bad = [proof[0][:-1] + bytes([proof[0][-1] ^ 1])] + proof[1:]
            assert not verify_inclusion(t.leaves[i], i, size, bad, root)
            assert not verify_inclusion(t.leaves[i], i, size, proof[:-1], root)


@settings(max_examples=60, deadline=None)
@given(st.integers(1, 70), st.integers(0, 70))
def test_consistency_proofs_for_all_size_pairs(second, first):
    first = min(first, second)
    t = MerkleTree()
    for i in range(second):
        t.append(f"e{i}".encode())
    proof = t.consistency_proof(first, second)
    assert verify_consistency(first, second, proof, t.root(first), t.root(second))
    if 0 < first < second:
        forged = t.root(first)[:-1] + bytes([t.root(first)[-1] ^ 1])
        assert not verify_consistency(first, second, proof, forged, t.root(second))
        assert not verify_consistency(first, second, proof, t.root(first), t.root(second)[:-1] + b"\x00")
        assert not verify_consistency(first, second, proof[:-1], t.root(first), t.root(second))


def test_a_rewritten_history_has_no_consistency_proof():
    a, b = MerkleTree(), MerkleTree()
    for i in range(10):
        a.append(f"e{i}".encode())
        b.append((f"e{i}" if i != 3 else "EDITED").encode())
    proof = b.consistency_proof(6, 10)
    assert not verify_consistency(6, 10, proof, a.root(6), b.root(10))


def test_signed_heads_and_truncation_detection(tmp_path):
    key = Ed25519PrivateKey.generate()
    log = AuditLog(tmp_path / "a.jsonl", signing_key=key)
    for i in range(6):
        log.append("alice", f"act{i}", "allow")
    pinned = log.checkpoint(tmp_path / "heads.jsonl")
    assert verify_head_signature(pinned, key.public_key())
    assert not verify_head_signature(pinned, Ed25519PrivateKey.generate().public_key())
    for i in range(6, 10):
        log.append("alice", f"act{i}", "allow")
    assert verify_against_head(log.entries, pinned, key.public_key())[0]        # grew append-only
    assert not verify_against_head(log.entries[:4], pinned, key.public_key())[0]  # truncated tail
    # attacker edits history and recomputes every hash so the local chain is internally valid
    forged = AuditLog()
    for e in log.entries:
        forged.append(e["principal"], "FORGED" if e["seq"] == 2 else e["action"], e["decision"])
    assert forged.entries[-1]["seq"] == 9
    ok, msg = verify_against_head(forged.entries, pinned, key.public_key())
    assert not ok and "rewritten" in msg
    bad = type(pinned)(pinned.size, pinned.root, pinned.time, pinned.sig[:-2] + ("ff" if pinned.sig[-2:] == "00" else "00"))
    assert not verify_against_head(log.entries, bad, key.public_key())[0]
    assert sign_head(MerkleTree(), key).size == 0


def test_inclusion_proof_of_a_real_audit_entry():
    log = AuditLog()
    for i in range(13):
        log.append("p", f"a{i}", "allow", {"i": i})
    seq = 7
    proof = log.tree.inclusion_proof(seq)
    assert verify_inclusion(leaf_hash(log.entries[seq]["hash"].encode()), seq, 13, proof, log.tree.root())
