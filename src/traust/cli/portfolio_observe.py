"""Routing intake materializers: configured repositories, operator events, and forge state."""

from __future__ import annotations

from pathlib import Path

from traust_core.v1.models.operations import AssetRequest

from traust.cli._doors import answer, parser
from traust.context import findings_tree_dir, load, load_caller
from traust.ops.intake import InventoryDiscoveryMaterializer, RescanEventIntakeMaterializer
from traust.ops.materializers import MANUAL, RepoStateMaterializer


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "observe", "Observe a repository at its forge; keep what it answered.")
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this observation is for")
    args = ap.parse_args(argv)
    core = load(args.config_home)
    materializer = RepoStateMaterializer(core.services(), core.config.forge_hosts)
    return answer(
        materializer.materialize(
            AssetRequest(asset=materializer.asset, run_id=args.run_id, partition=args.repo)
        )
    )


def inventory_discover(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "inventory-discover",
        "Register configured input repositories and plan their first observation and audit.",
    )
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    with core.repository_observation() as observation:
        materializer = InventoryDiscoveryMaterializer(
            core.services(), observation.query, core.repository_inventory(), load_caller(core)
        )
        return answer(
            materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
        )


def event_intake(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "event-intake",
        "Plan unconsumed external-report, methodology, and CVE events.",
    )
    ap.add_argument("--events", type=Path, help="override the configured rescan-events.jsonl")
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    events = args.events or findings_tree_dir(core) / "_manifest" / "rescan-events.jsonl"
    with core.repository_observation() as observation:
        materializer = RescanEventIntakeMaterializer(
            core.services(), observation.query, load_caller(core), events
        )
        return answer(
            materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
        )
