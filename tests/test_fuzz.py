"""Fuzz the whole governed surface: random principals x random operations x random (often hostile)
arguments. Invariants after every step: no restricted value is ever returned; the only exceptions are
the two governed denial types; the audit chain verifies; provenance matches applied change sets."""
import json

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from ontolite.actions import ActionDenied
from ontolite.audit.verify import verify_entries
from ontolite.retrieval import AccessDenied

from .conftest import build

TYPES = ["Company", "Filing", "Fact", "Concept", "Nope", ""]
KEYS = ["0000320193", "0000789019", "0000999999", "0000320193-26-000001", "0000789019-26-000002",
        "0000999999-26-000003", "Revenues", "x", "", "0000999999|Revenues", "' OR 1=1 --", "../../etc/passwd"]
LINKS = ["filings", "facts", "concept", "company", "filing", "facts_of_concept", "bogus"]
TEXTS = ["", "SENTINEL", "RISK", "NOTE", "SECRETCO", "0000999999", "7372", "6770", "%", "_", "\\", "'", "\u0000", "RED"]
PROPS = ["cik", "name", "risk_rating", "internal_notes", "value", "tag", "adsh", "nope", None]
FORBIDDEN = {  # strings each (non-reviewer) principal must never receive
    "alice": ["SENTINEL", "SECRETCO", "0000999999", "777.0", "6770"],
    "agent-alice": ["SENTINEL", "SECRETCO", "0000999999", "777.0", "6770"],
    "walter": ["SENTINEL", "SECRETCO", "0000999999", "777.0", "6770", "EXAMPLE SOFT", "0000789019", "7372", "2000.0"],
}
WHO = st.sampled_from(["alice", "agent-alice", "walter", "ghost", "orphan-agent"])


class GovernedSurface(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        self.rt = build("sqlite")
        self.handles: list[tuple[str, str]] = []
        self.applied = 0

    def _run(self, who, fn):
        try:
            out = fn()
        except (AccessDenied, ActionDenied):
            return
        blob = json.dumps(out, default=str)
        for bad in FORBIDDEN.get(who, ["SENTINEL", "SECRETCO", "0000999999"]):
            assert bad not in blob, (who, bad, blob[:200])

    @rule(who=WHO, t=st.sampled_from(TYPES), text=st.sampled_from(TEXTS), f=st.sampled_from(PROPS), limit=st.integers(-5, 500))
    def search(self, who, t, text, f, limit):
        filters = {f: text} if f else None
        self._run(who, lambda: self.rt.retriever.search(who, t, text, filters, limit))

    @rule(who=WHO, t=st.sampled_from(TYPES), k=st.sampled_from(KEYS))
    def get(self, who, t, k):
        self._run(who, lambda: self.rt.retriever.get(who, t, k))

    @rule(who=WHO, t=st.sampled_from(TYPES), k=st.sampled_from(KEYS), link=st.sampled_from(LINKS))
    def traverse(self, who, t, k, link):
        self._run(who, lambda: self.rt.retriever.traverse(who, t, k, link))

    @rule(who=WHO, t=st.sampled_from(TYPES), op=st.sampled_from(["count", "sum", "avg", "min", "max", "median"]),
          p=st.sampled_from(PROPS), text=st.sampled_from(TEXTS))
    def query(self, who, t, op, p, text):
        self._run(who, lambda: self.rt.retriever.query(who, t, op, p, {"name": text} if text else None))

    @rule(who=WHO, name=st.sampled_from(["revenue_by_filing", "average_by_tag", "companies_by_risk", "zzz"]),
          tag=st.sampled_from(["Revenues", "NetIncomeLoss", "", "x'--"]))
    def run_query(self, who, name, tag):
        self._run(who, lambda: self.rt.retriever.run_query(who, name, {"tag": tag} if name != "companies_by_risk" else {}))

    @rule(who=WHO, action=st.sampled_from(["flag_for_review", "request_signoff", "nope"]),
          adsh=st.sampled_from(KEYS), reason=st.sampled_from(["r", "", "SENTINEL", "\u0000"]))
    def propose(self, who, action, adsh, reason):
        try:
            cs = self.rt.actions.propose(who, action, {"adsh": adsh, "reason": reason} if action == "flag_for_review" else {"adsh": adsh})
            self.handles.append((who, cs.handle))
        except (ActionDenied, AccessDenied):
            pass

    @rule(who=WHO, i=st.integers(0, 20))
    def apply(self, who, i):
        if not self.handles:
            return
        owner, handle = self.handles[i % len(self.handles)]
        try:
            self.rt.actions.apply(who, handle)
            assert who == owner                      # only the proposing principal can ever apply a handle
            self.applied += 1
        except (ActionDenied, AccessDenied):
            pass

    @invariant()
    def audit_chain_and_provenance_are_consistent(self):
        if not hasattr(self, "rt"):
            return
        assert verify_entries(self.rt.audit.entries)[0]
        assert len({r[0] for r in self.rt.store.provenance()}) == self.applied


TestGovernedSurface = GovernedSurface.TestCase
TestGovernedSurface.settings = settings(max_examples=40, stateful_step_count=30, deadline=None,
                                        suppress_health_check=list(HealthCheck))
