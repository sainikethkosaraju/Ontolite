"""ontolite init | ingest | propose | schema diff | apply | serve | audit verify"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from ontolite.audit import verify_audit
from ontolite.ingest.sec_loader import load_sec
from ontolite.propose import ApprovalGate, MockModel, NotApproved, propose_schema_change
from ontolite.runtime import Ontolite
from ontolite.schema import diff_schemas, load_schema

DEMO = Path(__file__).resolve().parents[2] / "demo" / "sec"
STATE = ".ontolite"


def _paths(d: str) -> dict[str, Path]:
    base = Path(d)
    return {"schema": base / "schema.yaml", "principals": base / "principals.yaml",
            "mappings": base / "mappings.yaml", "db": base / "ontolite.db",
            "audit": base / "audit.jsonl"}


def _open(d: str) -> Ontolite:
    p = _paths(d)
    return Ontolite.open(p["schema"], p["principals"], str(p["db"]), p["audit"])


def cmd_init(a: argparse.Namespace) -> int:
    dest = Path(a.dir)
    dest.mkdir(parents=True, exist_ok=True)
    for f in ("schema.yaml", "principals.yaml", "mappings.yaml"):
        shutil.copy(DEMO / f, dest / f)
    if (DEMO / "sample").exists():
        shutil.copytree(DEMO / "sample", dest / "data", dirs_exist_ok=True)
    (dest / "audit.jsonl").touch()
    print(f"initialised demo project in {dest}")
    return 0


def cmd_ingest(a: argparse.Namespace) -> int:
    rt = _open(a.dir)
    p = _paths(a.dir)
    counts = load_sec(rt.schema, rt.store, a.data or Path(a.dir) / "data", p["mappings"])
    print(json.dumps(counts, indent=2))
    return 0


def cmd_schema_diff(a: argparse.Namespace) -> int:
    print(diff_schemas(load_schema(a.old), load_schema(a.new)).render())
    return 0


def cmd_propose(a: argparse.Namespace) -> int:
    rt = _open(a.dir)
    model = MockModel(Path(a.from_file).read_text())  # no live model: proposal read from a file
    prop = propose_schema_change(model, rt.schema, a.request)
    print(f"proposal {prop.id} (pending approval)\n{prop.diff.render()}")
    if a.approve_as:
        try:
            ApprovalGate(rt.checker).approve(prop, a.approve_as)
            ApprovalGate(rt.checker).apply(prop, rt)
        except NotApproved as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        print("approved and applied (in-memory; write the new schema.yaml to persist)")
    return 0


def cmd_apply(a: argparse.Namespace) -> int:
    rt = _open(a.dir)
    cs = rt.actions.apply(a.principal, a.handle)
    print(json.dumps({"ref": cs.ref, "status": cs.status, "edits": cs.edits}, indent=2))
    return 0


def cmd_serve(a: argparse.Namespace) -> int:
    from ontolite.mcp_server import build_server
    principal = a.principal or os.environ.get("ONTOLITE_PRINCIPAL", "")
    if not principal:
        print("set --principal or ONTOLITE_PRINCIPAL", file=sys.stderr)
        return 2
    build_server(_open(a.dir), principal).run("stdio")
    return 0


def cmd_audit_verify(a: argparse.Namespace) -> int:
    ok, msg = verify_audit(a.path or _paths(a.dir)["audit"], a.head)
    print(msg)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ontolite")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("init", cmd_init), ("ingest", cmd_ingest)):
        s = sub.add_parser(name); s.add_argument("--dir", default=STATE)
        if name == "ingest":
            s.add_argument("--data")
        s.set_defaults(fn=fn)
    s = sub.add_parser("schema"); ss = s.add_subparsers(dest="sub", required=True)
    d = ss.add_parser("diff"); d.add_argument("old"); d.add_argument("new"); d.set_defaults(fn=cmd_schema_diff)
    s = sub.add_parser("propose"); s.add_argument("--dir", default=STATE)
    s.add_argument("--from-file", required=True); s.add_argument("--request", default="")
    s.add_argument("--approve-as"); s.set_defaults(fn=cmd_propose)
    s = sub.add_parser("apply"); s.add_argument("--dir", default=STATE)
    s.add_argument("--principal", required=True); s.add_argument("handle"); s.set_defaults(fn=cmd_apply)
    s = sub.add_parser("serve"); s.add_argument("--dir", default=STATE)
    s.add_argument("--principal"); s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("audit"); au = s.add_subparsers(dest="sub", required=True)
    v = au.add_parser("verify"); v.add_argument("--dir", default=STATE); v.add_argument("path", nargs="?")
    v.add_argument("--head"); v.set_defaults(fn=cmd_audit_verify)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
