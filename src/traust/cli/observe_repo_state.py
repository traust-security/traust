"""Observe and store one repository's facts without selecting or dispatching work."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from sqlalchemy import URL
from sqlalchemy.exc import SQLAlchemyError
from traust_core.v1.domain import RepositoryError, SystemClock
from traust_core.v1.repositories.sql import create_database_engine

from traust.context import add_config_home_arg, analysis_results_dir, load_engine
from traust_pack_security.observe import LegacyForgeClient, observe_repo
from traust_pack_security.repos.observation_inputs import LegacyObservationInputs
from traust_pack_security.repos.repo_state import RepoStateUnitOfWork, initialize_repo_state


def add_args(parser: argparse.ArgumentParser) -> None:
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", help="repository URL")
    target.add_argument("--repo-key", help="audit key, including records without a URL")
    parser.add_argument("--db", type=Path, help="read-only findings.db projection")
    parser.add_argument("--graph-db", type=Path, help="inventory portfolio-graph.db")
    parser.add_argument("--designations", type=Path, help="read-only exposure designations")
    parser.add_argument("--state-db", type=Path, help="separate SQLite observation store")
    parser.add_argument("--no-network", action="store_true")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(parser)
    add_args(parser)
    args = parser.parse_args(argv)

    root = None
    if args.db is None or args.state_db is None:
        root = analysis_results_dir(load_engine(args.config_home))
    findings = args.db or root / "graph" / "findings.db"
    state_path = args.state_db or root / "graph" / "repo-state.db"
    graph = args.graph_db or findings.with_name("portfolio-graph.db")
    designations = (
        args.designations
        or findings.parent.parent / "findings" / "_manifest" / "exposure-designations.json"
    )
    # The input projection stays read-only, including when the operator supplies
    # an accidental alias/symlink to it as the new output database.
    if state_path.resolve() in {findings.resolve(), graph.resolve()}:
        parser.error("--state-db must be separate from the findings and inventory projections")
    engine = None
    try:
        source = LegacyObservationInputs(findings, graph, designations)
        repo = source.find(repo_url=args.repo, repo_key=args.repo_key)
        state = observe_repo(
            repo, LegacyForgeClient(), SystemClock().now(), network=not args.no_network
        )
        state_path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_database_engine(URL.create("sqlite", database=str(state_path)))
        initialize_repo_state(engine)
        with RepoStateUnitOfWork(engine) as uow:
            uow.repo_state.save(state)
            uow.commit()
        doc = state.model_dump(mode="json")
        doc["repo"] = str(state.repo) if state.repo else None
        print(json.dumps(doc, indent=2, allow_nan=False))
        return 0
    except (
        OSError,
        ValueError,
        LookupError,
        sqlite3.Error,
        SQLAlchemyError,
        RepositoryError,
    ) as exc:
        print(f"repo-state: {exc}", file=sys.stderr)
        return 2
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
