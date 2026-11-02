"""Independent reference implementation: bottom-up materialisation to a fixpoint (the engine is
top-down with memoisation, so this checks the algorithm, not just examples)."""
from ontolite.authz.model import TTU, Computed, Exclusion, Intersection, LinkSet, This, Union_


def materialise(ns, live, users, link_pairs=None, objects_extra=()):
    """live: [(obj, rel, subj)]; returns {(obj, rel): set(users)}."""
    link_pairs = link_pairs or {}
    objs = {o for o, _, _ in live} | {s.split("#")[0] for _, _, s in live if "#" in s and not s.endswith(":*")}
    objs |= {s for _, _, s in live if "#" not in s and not s.endswith(":*")} | set(objects_extra)
    S = {}
    keys = [(o, r) for o in objs for r in (ns[o.split(":")[0]].relations if o.split(":")[0] in ns else {})]
    for k in keys:
        S[k] = set()

    def targets(obj, tupleset):
        t = obj.split(":")[0]
        rw = ns[t].relations[tupleset]
        out = [s for (o, r, s) in live if o == obj and r == tupleset and "#" not in s and not s.endswith(":*")]
        if isinstance(rw, LinkSet):
            out += link_pairs.get((obj, rw.name), [])
        return out

    def ev(rw, obj, rel):
        if isinstance(rw, This):
            res = set()
            for (o, r, s) in live:
                if o == obj and r == rel:
                    if s.endswith(":*"):
                        res |= {u for u in users if u.split(":")[0] == s.split(":")[0]}
                    elif "#" in s:
                        res |= S.get(tuple(s.split("#")), set())
                    else:
                        res.add(s)
            return res
        if isinstance(rw, Computed):
            return set(S.get((obj, rw.relation), set()))
        if isinstance(rw, TTU):
            res = set()
            for t in targets(obj, rw.tupleset):
                res |= S.get((t, rw.relation), set())
            return res
        if isinstance(rw, Union_):
            res = set()
            for c in rw.children:
                res |= ev(c, obj, rel)
            return res
        if isinstance(rw, Intersection):
            sets = [ev(c, obj, rel) for c in rw.children]
            return set.intersection(*sets)
        if isinstance(rw, Exclusion):
            return ev(rw.base, obj, rel) - ev(rw.subtract, obj, rel)
        return set()

    for _ in range(200):
        changed = False
        for (o, r) in keys:
            new = ev(ns[o.split(":")[0]].relations[r], o, r)
            if new != S[(o, r)]:
                S[(o, r)] = new
                changed = True
        if not changed:
            return S
    raise AssertionError("oracle did not converge")
