"""Generate the (synthetic, SEC-layout) benchmark dataset deterministically. Run: python demo/bench/make_data.py"""
import random
from pathlib import Path

OUT = Path(__file__).parent / "data"
OUT.mkdir(exist_ok=True)
rng = random.Random(2026)
COMPANIES = [("0000100001", "EXAMPLE FRUIT CO", "3571"), ("0000100002", "EXAMPLE SOFT CORP", "7372"),
             ("0000100003", "EXAMPLE AUTO INC", "3711"), ("0000100004", "EXAMPLE BANK CORP", "6021"),
             ("0000100005", "EXAMPLE ENERGY LTD", "1311"), ("0000999999", "SECRETCO HOLDINGS", "6770")]
TAGS = [("Revenues", "Revenues"), ("NetIncomeLoss", "Net Income (Loss)"), ("Assets", "Assets"), ("Liabilities", "Liabilities")]
sub = ["adsh\tcik\tname\tsic\tform\tperiod\tfiled\tfy"]
num = ["adsh\ttag\tversion\tddate\tqtrs\tuom\tvalue"]
ic = ["cik\trisk_rating"]
inf = ["adsh\tinternal_notes"]
for i, (cik, name, sic) in enumerate(COMPANIES):
    ic.append(f"{cik}\tSENTINEL-RISK-{['AMBER','GREEN','AMBER','RED','GREEN','BLACK'][i]}")
    for j, (form, period, filed, qtrs) in enumerate([("10-K", "20251231", "20260215", 4), ("10-Q", "20260331", "20260510", 1)]):
        adsh = f"{cik}-26-{j + 1:06d}"
        sub.append(f"{adsh}\t{cik}\t{name}\t{sic}\t{form}\t{period}\t{filed}\t2025" if j == 0 else
                   f"{adsh}\t{cik}\t{name}\t{sic}\t{form}\t{period}\t{filed}\t2026")
        inf.append(f"{adsh}\tSENTINEL-NOTE-{cik[-2:]}-{j + 1}")
        for tag, _ in TAGS:
            v = rng.randrange(1000, 90000) * (1 if j == 0 else 1)
            num.append(f"{adsh}\t{tag}\tus-gaap/2025\t{period}\t{qtrs}\tUSD\t{v}")
(OUT / "sub.txt").write_text("\n".join(sub) + "\n")
(OUT / "num.txt").write_text("\n".join(num) + "\n")
(OUT / "tag.txt").write_text("tag\ttlabel\tdatatype\n" + "\n".join(f"{t}\t{lab}\tmonetary" for t, lab in TAGS) + "\n")
(OUT / "internal_companies.tsv").write_text("\n".join(ic) + "\n")
(OUT / "internal_filings.tsv").write_text("\n".join(inf) + "\n")
print("wrote", OUT)
