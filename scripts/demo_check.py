"""Sanity-check a freshly ingested demo store: counts per type, the audit chain, and one governed query per principal.
Usage: python scripts/demo_check.py .ontolite"""
import sys

from ontolite.audit import verify_audit
from ontolite.cli import _open

d = sys.argv[1] if len(sys.argv) > 1 else ".ontolite"
rt = _open(d)
print("objects:", {t: rt.store.count(t) for t in rt.schema.objects})
assert rt.store.count("Fact") > 0 and rt.store.count("Filing") > 0, "ingest produced no facts/filings"
seen = {}
for who in ("alice", "walter", "rita"):
    comps = rt.retriever.search(who, "Company", limit=200)
    facts = rt.retriever.query(who, "Fact", "count")["value"]
    seen[who] = (len(comps), facts, [c.get("name") for c in comps[:3]], any("risk_rating" in c for c in comps))
    print(f"{who}: sees {len(comps)} companies, {facts} facts, risk_rating visible: {seen[who][3]}; first: {seen[who][2]}")
# the governance claims, on REAL data
assert seen["alice"][1] > 0 and seen["rita"][1] >= seen["alice"][1] > seen["walter"][1] > 0, "wall/role differences not visible"
assert seen["rita"][3] and not seen["alice"][3] and not seen["walter"][3], "restricted property leaked or missing"
rows = rt.retriever.run_query("rita", "revenue_by_filing", {"tag": "Assets"})["rows"][:3]
print("rita revenue_by_filing(Assets) sample:", rows)
ok, msg = verify_audit(f"{d}/audit.jsonl")
print("audit:", msg)
assert ok
