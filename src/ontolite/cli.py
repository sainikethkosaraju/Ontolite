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


def _open(d: str, backend: str = "sqlite", key: str | None = None) -> Ontolite:
    p = _paths(d)
    signing = _load_private(key) if key else None
    return Ontolite.open(p["schema"], p["principals"], str(p["db"]), p["audit"],
                         authz_path=Path(d) / "authz.yaml", backend=backend, signing_key=signing)


def _load_private(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(Path(path).read_bytes(), password=None)


def _load_public(path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(Path(path).read_bytes())


def cmd_init(a: argparse.Namespace) -> int:
    dest = Path(a.dir)
    dest.mkdir(parents=True, exist_ok=True)
    for f in ("schema.yaml", "principals.yaml", "mappings.yaml", "authz.yaml"):
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
            touched = ApprovalGate(rt.checker).apply(prop, rt, allow_destructive=a.allow_destructive)
            print(f"migration touched: {touched or 'no data'}")
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
    rt = _open(a.dir, a.backend, a.key)
    if a.transport == "http":
        import uvicorn

        from ontolite.http_auth import TokenFile
        url = f"http://{a.host}:{a.port}/mcp"
        app = build_server(rt, token_verifier=TokenFile(Path(a.dir) / "tokens.json"), resource_url=url).streamable_http_app()
        print(f"serving {url} (bearer tokens from {a.dir}/tokens.json; issue with `ontolite token issue`)")
        uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
        return 0
    principal = a.principal or os.environ.get("ONTOLITE_PRINCIPAL", "")
    if not principal:
        print("set --principal or ONTOLITE_PRINCIPAL", file=sys.stderr)
        return 2
    build_server(rt, principal).run("stdio")
    return 0


def cmd_audit_verify(a: argparse.Namespace) -> int:
    path = a.path or _paths(a.dir)["audit"]
    if a.pinned:
        from ontolite.audit import SignedTreeHead, verify_against_head
        entries = [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]
        heads = [SignedTreeHead.from_json(x) for x in Path(a.pinned).read_text().splitlines() if x.strip()]
        if not heads or not a.pubkey:
            print("--pinned needs a non-empty checkpoint file and --pubkey", file=sys.stderr)
            return 2
        for h in heads:    # every pinned head must still be a prefix of the log
            ok, msg = verify_against_head(entries, h, _load_public(a.pubkey))
            if not ok:
                print(f"head at size {h.size}: {msg}")
                return 1
        print(msg)
        return 0
    ok, msg = verify_audit(path, a.head)
    print(msg)
    return 0 if ok else 1


def cmd_audit_keygen(a: argparse.Namespace) -> int:
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    out = Path(a.out)
    out.write_bytes(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    out.chmod(0o600)
    out.with_suffix(".pub").write_bytes(k.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    print(f"wrote {out} (private, 0600) and {out.with_suffix('.pub')}")
    return 0


def cmd_audit_checkpoint(a: argparse.Namespace) -> int:
    rt = _open(a.dir, key=a.key)
    sth = rt.audit.checkpoint(a.out)
    print(f"signed head: size={sth.size} root={sth.root[:16]}... -> {a.out} (publish it OFF this machine)")
    return 0


def cmd_audit_prove(a: argparse.Namespace) -> int:
    from ontolite.audit.merkle import leaf_hash
    rt = _open(a.dir)
    proof = rt.audit.tree.inclusion_proof(a.seq)
    print(json.dumps({"seq": a.seq, "size": len(rt.audit.tree), "root": rt.audit.tree.root().hex(),
                      "leaf": leaf_hash(rt.audit.entries[a.seq]["hash"].encode()).hex(),
                      "proof": [p.hex() for p in proof]}))
    return 0


def cmd_authz(a: argparse.Namespace) -> int:
    rt = _open(a.dir)
    if a.sub == "check":
        ok = rt.authz.check(a.obj, a.rel, a.user)
        print("ALLOWED" if ok else "DENIED")
        return 0 if ok else 1
    print("\n".join(sorted(rt.authz.who_can(a.obj, a.rel))) or "(nobody)")
    return 0


def cmd_token(a: argparse.Namespace) -> int:
    from ontolite.http_auth import TokenFile
    tf = TokenFile(Path(a.dir) / "tokens.json")
    if a.sub == "issue":
        print(tf.issue(a.principal, a.ttl))
        return 0
    print("revoked" if tf.revoke(a.token) else "unknown token")
    return 0


def cmd_migrate_plan(a: argparse.Namespace) -> int:
    from ontolite.schema.migrate import plan
    renames = dict(r.split("=", 1) for r in (a.rename or []))
    m = plan(load_schema(a.old), load_schema(a.new), renames)
    print(m.describe())
    return 1 if m.destructive else 0


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
    s.add_argument("--approve-as"); s.add_argument("--allow-destructive", action="store_true")
    s.set_defaults(fn=cmd_propose)
    s = sub.add_parser("apply"); s.add_argument("--dir", default=STATE)
    s.add_argument("--principal", required=True); s.add_argument("handle"); s.set_defaults(fn=cmd_apply)
    s = sub.add_parser("serve"); s.add_argument("--dir", default=STATE)
    s.add_argument("--principal"); s.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--backend", choices=["sqlite", "duckdb"], default="sqlite"); s.add_argument("--key")
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("authz"); az = s.add_subparsers(dest="sub", required=True)
    c = az.add_parser("check"); c.add_argument("obj"); c.add_argument("rel"); c.add_argument("user")
    w = az.add_parser("who-can"); w.add_argument("obj"); w.add_argument("rel")
    for x in (c, w):
        x.add_argument("--dir", default=STATE); x.set_defaults(fn=cmd_authz)
    s = sub.add_parser("token"); tk = s.add_subparsers(dest="sub", required=True)
    i = tk.add_parser("issue"); i.add_argument("principal"); i.add_argument("--ttl", type=float, default=3600)
    r = tk.add_parser("revoke"); r.add_argument("token")
    for x in (i, r):
        x.add_argument("--dir", default=STATE); x.set_defaults(fn=cmd_token)
    s = sub.add_parser("migrate"); mg = s.add_subparsers(dest="sub", required=True)
    pl = mg.add_parser("plan"); pl.add_argument("old"); pl.add_argument("new")
    pl.add_argument("--rename", action="append", metavar="Type.old=new"); pl.set_defaults(fn=cmd_migrate_plan)
    s = sub.add_parser("audit"); au = s.add_subparsers(dest="sub", required=True)
    v = au.add_parser("verify"); v.add_argument("--dir", default=STATE); v.add_argument("path", nargs="?")
    v.add_argument("--head"); v.add_argument("--pinned", help="file of signed tree heads to check append-only against")
    v.add_argument("--pubkey"); v.set_defaults(fn=cmd_audit_verify)
    k = au.add_parser("keygen"); k.add_argument("--out", default="audit.key"); k.set_defaults(fn=cmd_audit_keygen)
    cp = au.add_parser("checkpoint"); cp.add_argument("--dir", default=STATE); cp.add_argument("--key", required=True)
    cp.add_argument("--out", default="heads.jsonl"); cp.set_defaults(fn=cmd_audit_checkpoint)
    pr = au.add_parser("prove"); pr.add_argument("seq", type=int); pr.add_argument("--dir", default=STATE)
    pr.set_defaults(fn=cmd_audit_prove)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
