from __future__ import annotations

from pathlib import Path
from typing import cast

from traust_core.v1.models.insight import CompliancePrecision, ViewFilter, ViewName
from traust_core.v1.models.vocabulary import ComplianceFramework

from traust.cli._doors import parser, run
from traust.cli._report_files import report_paths, write_reports
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "compliance-precision", "Report recorded compliance field precision.")
    ap.add_argument("--framework", required=True, choices=[f.value for f in ComplianceFramework])
    ap.add_argument("--gate", type=float, default=0.5, help="flag precision at or below this gate")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    def call() -> dict:
        scope = ViewFilter(
            framework=ComplianceFramework(args.framework),
            precision_gate=args.gate,
        )
        paths = report_paths(
            tuple(
                args.out_dir / f"compliance-precision.{suffix}" for suffix in ("json", "md", "html")
            )
        )
        rendered = (
            load(args.config_home).services().insight.publish(ViewName.COMPLIANCE_PRECISION, scope)
        )
        report = cast(CompliancePrecision, rendered.model).calibration
        write_reports(
            {
                paths[0]: report.model_dump_json(indent=2) + "\n",
                paths[1]: rendered.markdown,
                paths[2]: rendered.html,
            }
        )
        return {
            **report.model_dump(mode="json"),
            "flagged_checks": [check.check_id for check in report.checks if check.flagged],
        }

    return run(call)


if __name__ == "__main__":
    raise SystemExit(main())
