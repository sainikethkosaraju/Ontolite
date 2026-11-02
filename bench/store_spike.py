"""Store spike (blueprint T2.3): SQLite vs DuckDB on SEC-shaped synthetic data.
Usage: python bench/store_spike.py [companies] [filings_per_company] [facts_per_filing]
Writes a JSON result to stdout. Numbers are medians of 5 runs on THIS machine; see docs/adr/001-store.md."""
import json
import os
import platform
import random
import statistics
import sys
import time

from ontolite.store import Cond, Reach, open_store

C = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
FPC = int(sys.argv[2]) if len(sys.argv) > 2 else 10
FPF = int(sys.argv[3]) if len(sys.argv) > 3 else 15
TYPES = {"id": "string", "tag": "string", "value": "number", "uom": "string", "adsh": "string"}
TAGS = ["Revenues", "NetIncomeLoss", "Assets", "Liabilities", "StockholdersEquity", "OperatingIncomeLoss"]


def gen():
    rng = random.Random(42)
    comp, fil, facts, links = [], [], [], []
    for c in range(C):
        cik = f"{c:010d}"
        comp.append(("Company", cik, json.dumps({"cik": cik, "name": f"COMPANY {c}"})))
        for f in range(FPC):
            adsh = f"{cik}-26-{f:06d}"
            fil.append(("Filing", adsh, json.dumps({"adsh": adsh, "form": "10-K"})))
            links.append(("filings", cik, adsh))
            for t in range(FPF):
                fid = f"{adsh}|{TAGS[t % len(TAGS)]}|{t}"
                facts.append(("Fact", fid, json.dumps({"id": fid, "adsh": adsh, "tag": TAGS[t % len(TAGS)],
                                                       "value": round(rng.random() * 1e6, 2), "uom": "USD"})))
                links.append(("facts", adsh, fid))
    return comp, fil, facts, links


def timeit(fn, runs=5):
    ts = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    return round(statistics.median(ts), 2)


def run(backend, data):
    comp, fil, facts, links = data
    s = open_store(backend)
    t0 = time.perf_counter()
    with s.transaction():
        s.bulk_load(comp + fil + facts, links)
    load_s = time.perf_counter() - t0
    rng = random.Random(1)
    allowed_c = {f"{c:010d}" for c in rng.sample(range(C), int(C * 0.3))}
    reach = Reach(frozenset(allowed_c), (("filings", False), ("facts", False)))
    keyset = {x[1] for x in facts if x[1].split("-")[0] in allowed_c}  # the same 30%, as a materialised key list
    keys = [x[1] for x in rng.sample(facts, 1000)]
    vis = ["id", "tag", "value", "uom"]
    out = {"backend": backend, "load_seconds": round(load_s, 2),
           "rows": {"facts": len(facts), "filings": len(fil), "links": len(links)},
           "allowed_roots": len(allowed_c), "allowed_keys_if_materialised": len(keyset)}
    out["point_get_1000_ms"] = timeit(lambda: [s.get("Fact", k) for k in keys], 3)
    out["search_text__reach30_ms"] = timeit(lambda: s.select("Fact", "id", allowed=reach, visible=vis, types=TYPES, text="netincome", limit=20))
    out["search_text__keyset30_ms"] = timeit(lambda: s.select("Fact", "id", allowed=keyset, visible=vis, types=TYPES, text="netincome", limit=20))
    out["search_conds_unrestricted_ms"] = timeit(lambda: s.select(
        "Fact", "id", allowed=None, visible=vis, types=TYPES,
        conds=[Cond("tag", "eq", "Revenues"), Cond("value", "gt", 900000)], limit=20))
    out["agg_sum_by_tag__reach30_ms"] = timeit(lambda: s.aggregate("Fact", allowed=reach, types=TYPES, group_by=["tag"], op="sum", prop="value"))
    out["agg_sum_by_tag__keyset30_ms"] = timeit(lambda: s.aggregate("Fact", allowed=keyset, types=TYPES, group_by=["tag"], op="sum", prop="value"))
    out["agg_sum_by_tag_unrestricted_ms"] = timeit(lambda: s.aggregate("Fact", allowed=None, types=TYPES, group_by=["tag"], op="sum", prop="value"))
    fk = [x[1] for x in rng.sample(fil, 1000)]
    out["traverse_1000_ms"] = timeit(lambda: [s.neighbours("facts", k) for k in fk], 3)
    r1 = s.aggregate("Fact", allowed=reach, types=TYPES, group_by=["tag"], op="sum", prop="value")
    r2 = s.aggregate("Fact", allowed=keyset, types=TYPES, group_by=["tag"], op="sum", prop="value")
    out["reach_equals_keyset"] = [(r["tag"], round(r["value"], 2), r["n"]) for r in r1] == [(r["tag"], round(r["value"], 2), r["n"]) for r in r2]
    return out


if __name__ == "__main__":
    data = gen()
    res = {"env": {"python": platform.python_version(), "cpus": os.cpu_count(), "machine": platform.machine(),
                   "sqlite": __import__("sqlite3").sqlite_version, "duckdb": __import__("duckdb").__version__},
           "shape": {"companies": C, "filings_per_company": FPC, "facts_per_filing": FPF}, "results": []}
    for b in ("sqlite", "duckdb"):
        res["results"].append(run(b, data))
    print(json.dumps(res, indent=1))
