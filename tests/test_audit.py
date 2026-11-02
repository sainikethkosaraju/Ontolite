import json

from ontolite.audit import AuditLog, verify_audit
from ontolite.audit.verify import verify_entries


def make(path, n=5):
    log = AuditLog(path)
    for i in range(n):
        log.append("alice", f"act{i}", "allow", {"i": i})
    return log


def test_clean_log_verifies(tmp_path):
    p = tmp_path / "a.jsonl"
    make(p)
    assert verify_audit(p)[0]


def test_every_single_edit_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    make(p)
    lines = p.read_text().splitlines()
    for i in range(len(lines)):
        for field, val in [("principal", "mallory"), ("decision", "allow-forged"),
                           ("params_digest", "0" * 64), ("action", "x")]:
            e = json.loads(lines[i]); e[field] = val
            tampered = lines[:i] + [json.dumps(e, sort_keys=True)] + lines[i + 1:]
            q = tmp_path / f"t{i}{field}.jsonl"
            q.write_text("\n".join(tampered) + "\n")
            assert not verify_audit(q)[0], (i, field)


def test_deletion_and_reorder_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    make(p)
    lines = p.read_text().splitlines()
    for i in range(len(lines) - 1):  # deleting any non-final entry
        q = tmp_path / f"d{i}.jsonl"
        q.write_text("\n".join(lines[:i] + lines[i + 1:]) + "\n")
        assert not verify_audit(q)[0]
    q = tmp_path / "r.jsonl"
    q.write_text("\n".join([lines[1], lines[0], *lines[2:]]) + "\n")
    assert not verify_audit(q)[0]


def test_tail_truncation_needs_pinned_head(tmp_path):
    p = tmp_path / "a.jsonl"
    log = make(p)
    head = log.entries[-1]["hash"]
    lines = p.read_text().splitlines()
    q = tmp_path / "trunc.jsonl"
    q.write_text("\n".join(lines[:-1]) + "\n")
    assert verify_audit(q)[0]  # documented limitation without a pinned head
    assert not verify_audit(q, head)[0]
    assert verify_audit(p, head)[0]


def test_garbage_and_resume(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("{not json")
    assert not verify_audit(p)[0]
    q = tmp_path / "b.jsonl"
    make(q, 3)
    AuditLog(q).append("bob", "more", "allow")  # reopen and continue the chain
    assert verify_audit(q) == (True, "ok: 4 entries")
    assert verify_entries([])[0]


def test_runtime_actions_are_audited_and_chain_verifies(rt, tmp_path):
    rt.retriever.search("alice", "Company")
    try:
        rt.retriever.get("alice", "Company", "0000999999")
    except Exception:
        pass
    assert any(e["decision"].startswith("deny") for e in rt.audit.entries)
    assert verify_entries(rt.audit.entries)[0]
