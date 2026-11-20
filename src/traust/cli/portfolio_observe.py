"""Routing intake materializers: configured repositories, operator events, and forge state."""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

from traust_core.v1.errors import ConfigError, NotFoundError, TraustError, ValidationError
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason, RecordKind
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import (
    add_lease_generation_arg,
    add_materializer_lease_args,
    answer,
    materialize_repository,
    parser,
    scoped_recording_order,
)
from traust.context import findings_tree_dir, inputs_dir, load, load_caller
from traust.inventory import repository_inventory
from traust.ops.intake import (
    InventoryDiscoveryMaterializer,
    RescanEventIntakeMaterializer,
    external_validation_input,
)
from traust.ops.materializers import MANUAL, RepoStateMaterializer

log = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "observe", "Observe a repository at its forge; keep what it answered.")
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    add_materializer_lease_args(ap)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    materializer = RepoStateMaterializer(core.services())
    return materialize_repository(args, materializer)


def inventory_discover(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "inventory-discover",
        "Register configured input repositories and plan their first observation and audit.",
    )
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    try:
        inventory = repository_inventory(inputs_dir(core))
    except ConfigError as error:
        log.warning("run %s: inventory loading refused (%s)", args.run_id, type(error).__name__)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    with core.repository_observation() as observation:
        materializer = InventoryDiscoveryMaterializer(
            core.services(), observation.query, inventory, load_caller(core)
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


def event_validate(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "event-validate",
        "Run the explicitly scoped live-validation stage of an external report order.",
    )
    ap.add_argument("--role", required=True)
    ap.add_argument("--run-id", required=True)
    add_lease_generation_arg(ap)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    try:
        order_id = UUID(args.run_id)
        order = scoped_recording_order(
            core,
            order_id,
            RecordKind.VALIDATION,
            SourceType.VALIDATION_REPORT,
            args.lease_generation,
        )
        if order.asset != "external_report_validation" or order.event_source != "external-report":
            raise ValidationError("run order is not external report validation")
        validation = external_validation_input(core.services().ops.manifest(order_id))
        written = tuple(
            str(row.id)
            for row in core.services().assessment.list_for_order(order_id)
            if row.kind == AssessmentKind.VALIDATION
        )
        if written:
            return answer(JobResult.succeeded(written=written))
    except ValueError:
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    except NotFoundError:
        return answer(JobResult.refused(OrderReason.NOT_FOUND))
    except (TraustError, OSError) as error:
        log.warning("validation order refused: %s", type(error).__name__)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    from traust.cli.session import run

    command = [
        "--skill",
        "validate-findings",
        "--role",
        args.role,
        "--run-id",
        args.run_id,
        "--lease-generation",
        str(args.lease_generation),
    ]
    if args.config_home is not None:
        command.extend(("--config-home", str(args.config_home)))
    command.extend(
        (
            "--",
            validation.report,
            "--targets",
            validation.targets,
            "--auto",
            "--replay-only",
        )
    )
    return run(command)
