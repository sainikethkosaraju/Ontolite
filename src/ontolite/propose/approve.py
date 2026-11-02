from __future__ import annotations

from ontolite.permissions.checks import Checker
from ontolite.propose.proposer import SchemaProposal, schema_digest


class NotApproved(Exception):
    pass


class ApprovalGate:
    """Human gate. Approval requires the `schema_admin` role and binds to the proposal digest."""

    ROLE = "schema_admin"

    def __init__(self, checker: Checker) -> None:
        self.checker = checker

    def approve(self, proposal: SchemaProposal, approver: str) -> None:
        eff = self.checker.resolve(approver)
        if eff is None or self.ROLE not in eff.roles or self.checker.store.principal(approver).kind != "user":  # type: ignore[union-attr]
            raise NotApproved("approver lacks schema_admin or is not a human user")
        if schema_digest(proposal.new_schema) != proposal.digest:
            raise NotApproved("proposal was modified after it was proposed")
        proposal.status, proposal.approved_by = "approved", approver

    def apply(self, proposal: SchemaProposal, runtime) -> None:
        if proposal.status != "approved" or not proposal.approved_by:
            raise NotApproved("schema proposal has not been approved")
        if schema_digest(proposal.new_schema) != proposal.digest:
            raise NotApproved("proposal was modified after approval")
        runtime.replace_schema(proposal.new_schema)
        proposal.status = "applied"
