from __future__ import annotations

from pathlib import Path

from traust_core.v1.models.vocabulary import ComplianceFramework

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "compliance-precision", "Report recorded compliance field precision.")
    ap.add_argument("--framework", required=True, choices=[f.value for f in ComplianceFramework])
    ap.add_argument("--gate", type=float, default=0.5, help="flag precision at or below this gate")
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args(argv)

    def call() -> dict:
        report = (
            load(args.config_home)
            .services()
            .detection_quality.calibrate_compliance(
                ComplianceFramework(args.framework), gate=args.gate
            )
        )
        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "compliance-precision.json").write_text(
            report.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        return {
            **report.model_dump(mode="json"),
            "flagged_checks": [check.check_id for check in report.checks if check.flagged],
        }

    return run(call)


if __name__ == "__main__":
    raise SystemExit(main())
