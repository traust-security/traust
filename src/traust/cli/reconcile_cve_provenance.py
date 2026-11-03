"""Reconcile recorded code audits with later published CVEs, dry-run by default."""

from __future__ import annotations

from pathlib import Path

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser(
        "feeds", "reconcile-cve-provenance", "Match code audits to later CVEs; dry-run by default."
    )
    ap.add_argument("--apply", action="store_true", help="record finding links (default: dry run)")
    ap.add_argument("--min-score", type=float, default=0.55, help="title similarity floor, 0 to 1")
    ap.add_argument(
        "--report", type=Path, help="write the full typed reconciliation result as JSON"
    )
    args = ap.parse_args(argv)

    def call() -> dict[str, object]:
        result = (
            load(args.config_home)
            .services()
            .exposure.reconcile_all_provenance(min_score=args.min_score, apply=args.apply)
        )
        if args.report is not None:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return result.model_dump(mode="json")

    return run(call)


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["feeds", "reconcile-cve-provenance", *sys.argv[1:]]))
