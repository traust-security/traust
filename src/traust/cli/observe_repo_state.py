"""Observe one repository through Core and print its current assembled state."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from traust_core.v1.context import Context
from traust_core.v1.errors import TraustError

from traust.context import add_config_home_arg, analysis_results_dir, load_engine


def add_args(parser: argparse.ArgumentParser) -> None:
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", help="repository URL")
    target.add_argument("--repo-key", help="audit key, including records without a URL")
    parser.add_argument("--db", type=Path, help="read-only findings.db projection")
    parser.add_argument("--graph-db", type=Path, help="inventory portfolio-graph.db")
    parser.add_argument("--designations", type=Path, help="read-only exposure designations")
    parser.add_argument(
        "--core-config",
        type=Path,
        required=True,
        help="Core traust.yaml with configured database and forge process settings",
    )
    parser.add_argument("--no-network", action="store_true")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(parser)
    add_args(parser)
    args = parser.parse_args(argv)
    try:
        findings = (
            args.db or analysis_results_dir(load_engine(args.config_home)) / "graph" / "findings.db"
        )
        graph = args.graph_db or findings.with_name("portfolio-graph.db")
        designations = (
            args.designations
            or findings.parent.parent / "findings" / "_manifest" / "exposure-designations.json"
        )
        ctx = Context.from_file(args.core_config)
        with ctx.repository_observation(
            findings, inventory_db=graph, designations=designations
        ) as portfolio:
            portfolio.record_forge_facts(
                repo_url=args.repo, repo_key=args.repo_key, network=not args.no_network
            )
            state = portfolio.repo_state(repo_url=args.repo, repo_key=args.repo_key)
        print(state.model_dump_json(indent=2))
        return 0
    except (OSError, ValueError, LookupError, TraustError) as exc:
        print(f"repo-state: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
