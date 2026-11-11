"""Human-gated external advisory replay over Core's recorded audit commits."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from traust_core.v1.errors import ValidationError

from traust.cli._doors import parser, run
from traust.context import load, load_caller


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "cve-replay", __doc__ or "")
    operations = ap.add_subparsers(dest="operation", required=True)
    monitor = operations.add_parser(
        "monitor", help="Discover new OSV advisories on audited commits"
    )
    monitor.add_argument(
        "--since",
        type=datetime.fromisoformat,
        help="First source watermark, with timezone; default: each recorded audit's time",
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
    oracle.add_argument("--evidence", help="Evidence supporting the human presence adjudication")
    args = ap.parse_args(argv)

    def call() -> object:
        if (
            args.operation == "monitor"
            and args.since is not None
            and args.since.utcoffset() is None
        ):
            raise ValidationError("--since must include a time zone")
        core = load(args.config_home)
        service = core.services().detection_quality
        if args.operation == "monitor":
            result = service.cve_replay(args.since)
        elif args.operation == "candidates":
            result = service.cve_replay_candidates()
        elif args.operation == "trends":
            result = service.cve_replay_trends()
        else:
            result = service.cve_replay_oracle(
                args.assessment,
                args.advisory,
                present_at_audit={"true": True, "false": False, "unknown": None}[
                    args.present_at_audit
                ],
                principal=load_caller(core) if args.present_at_audit != "unknown" else None,
                presence_evidence=args.evidence,
            )
        return result.model_dump(mode="json")

    return run(call)


if __name__ == "__main__":
    raise SystemExit(main())
