from __future__ import annotations

from pathlib import Path
from uuid import UUID

from traust_core.v1.models.insight import ViewFilter, ViewName

from traust.cli import _doors
from traust.cli._doors import parser, run, when
from traust.context import load
from traust.ops.materializers import write_view


def main(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio", "graph", "Export the native repository relationship graph and hub report."
    )
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--inputs", type=Path, help="override the configured inventory hierarchy source"
    )
    ap.add_argument("--product", action="append", default=[])
    ap.add_argument("--team-id", action="append", type=UUID, default=[])
    ap.add_argument(
        "--as-of", help="ISO time with a zone; inventory labels remain the current snapshot"
    )
    ap.add_argument("--exclude-segment", action="append", default=None)
    args = ap.parse_args(argv)

    def call() -> dict[str, object]:
        core = load(args.config_home)
        if args.inputs is not None:
            core.register_input_segments(args.inputs)
        services = core.services()
        filter = ViewFilter(
            product_ids=tuple(p.id for p in _doors.products(services, args.product)),
            team_ids=tuple(args.team_id),
            as_of=when(args.as_of),
            exclude_segments=tuple(args.exclude_segment)
            if args.exclude_segment is not None
            else ("ansible",),
        )
        rendered = services.insight.publish(ViewName.REPOSITORY_GRAPH, filter)
        written = list(write_view(rendered, args.out / "repo-graph", model=True))
        markdown = args.out / "repo-graph.md"
        statistics = args.out / "repo-graph-stats.md"
        markdown.replace(statistics)
        written[written.index(markdown)] = statistics
        return {
            "written": [str(path) for path in written],
            "stats": rendered.model.model_dump(mode="json")["stats"],
        }

    return run(call)


if __name__ == "__main__":
    raise SystemExit(main())
