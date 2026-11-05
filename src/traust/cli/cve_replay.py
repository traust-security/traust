"""Human-gated external advisory replay over Core's recorded audit commits.

Refused until traust-core decides where CVE replay lives (plan 15, decision 2).
"""

from __future__ import annotations

from uuid import UUID

from traust.cli._doors import parser, run
from traust.lib.pending_decisions import Decision, PendingCoreDecision


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "cve-replay", __doc__ or "")
    operations = ap.add_subparsers(dest="operation", required=True)
    monitor = operations.add_parser(
        "monitor", help="Discover new OSV advisories on audited commits"
    )
    monitor.add_argument(
        "--since", help="First source watermark, with timezone; default: each recorded audit's time"
    )
    operations.add_parser("candidates", help="Export the human-gated candidate queue as JSON")
    operations.add_parser("trends", help="Export presence-confirmed missed candidates as JSON")
    oracle = operations.add_parser("oracle", help="Check one advisory against one recorded audit")
    oracle.add_argument("assessment", type=UUID)
    oracle.add_argument("advisory", help="OSV advisory identifier or alias")
    oracle.add_argument(
        "--present-at-audit",
        choices=("true", "false", "unknown"),
        default="unknown",
        help="Human-adjudicated presence; unknown is never counted as a confirmed miss",
    )
    ap.parse_args(argv)

    def call() -> object:
        # No traust-core door yet: replaying advisories against recorded audits waits on decision 2.
        raise PendingCoreDecision(Decision.CVE_REPLAY)

    return run(call)


if __name__ == "__main__":
    raise SystemExit(main())
