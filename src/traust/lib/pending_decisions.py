"""Capabilities whose traust-core home waits on an owner decision: they fail closed.

The plan "traust runs on traust-core development again" (traust-standardization plan 15,
owner Michele, decisions Shaun's) keeps four capabilities out of traust-core until their owner
answers. Until then the traust commands that need them stay, and refuse with
:class:`PendingCoreDecision` naming the decision. They never read a fallback or do nothing.
"""

from __future__ import annotations

from enum import Enum

from traust_core.v1.errors import TraustError


class Decision(Enum):
    """Plan 15's open decisions, numbered as the plan numbers them."""

    CLAIM_CORRECTION = (1, "Claim correction")
    CVE_REPLAY = (2, "CVE replay")
    LIVENESS_STATUS = (3, "Liveness status")
    PQC_SCANNER = (4, "The pqc-scan scanner")

    @property
    def number(self) -> int:
        return self.value[0]

    @property
    def capability(self) -> str:
        return self.value[1]


class PendingCoreDecision(TraustError):
    """A capability traust-core does not offer until its pending decision is answered."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(
            f"{decision.capability} needs a traust-core decision"
            f" (plan 15, decision {decision.number})"
        )


def skip_reason(decision: Decision) -> str:
    """The skip reason a test of a pending capability carries."""
    return str(PendingCoreDecision(decision))
