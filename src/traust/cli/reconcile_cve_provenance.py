"""Reconcile recorded findings with later published CVEs, one finding at a time.

traust-core's ``ExposureService.reconcile_provenance`` matches a finding to the rh-cve feed and
records the best match as its advisory when the finding names none. It always records, so this
door refuses to run without ``--apply``: there is no dry run.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from traust_core.v1.errors import ValidationError

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser(
        "feeds", "reconcile-cve-provenance", "Match recorded findings to later CVEs and link them."
    )
    ap.add_argument(
        "--finding",
        action="append",
        type=UUID,
        default=[],
        help="a recorded finding to reconcile (repeatable, at least one)",
    )
    ap.add_argument(
        "--apply", action="store_true", help="required: the check records each best match"
    )
    ap.add_argument("--report", type=Path, help="write the typed checks as JSON")
    args = ap.parse_args(argv)

    def call() -> dict[str, object]:
        if not args.finding:
            raise ValidationError("name the findings to reconcile: --finding <uuid> (repeatable)")
        if not args.apply:
            raise ValidationError(
                "reconciliation records the best match as the finding's advisory; pass --apply"
            )
        exposure = load(args.config_home).services().exposure
        checks = [
            exposure.reconcile_provenance(finding_id).model_dump(mode="json")
            for finding_id in dict.fromkeys(args.finding)
        ]
        result: dict[str, object] = {"checks": checks}
        if args.report is not None:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result

    return run(call)


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["feeds", "reconcile-cve-provenance", *sys.argv[1:]]))
