"""``traust portfolio liveness``: the census artifact from recorded forge availability.

Each repository's status (active, archived, moved, missing, disabled, unknown) is the typed
repo-liveness reference's, which needs a newer traust-core contracts pin. Until that decision
(plan 15, decision 3) the command refuses rather than derive a status traust-core never recorded.
"""

from __future__ import annotations

from typing import Any

from traust.cli._doors import parser, run
from traust.lib.pending_decisions import Decision, PendingCoreDecision


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "liveness", "Each repository's last observed forge availability.")
    ap.parse_args(argv)

    def call() -> Any:
        raise PendingCoreDecision(Decision.LIVENESS_STATUS)

    return run(call)
