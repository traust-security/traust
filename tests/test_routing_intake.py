from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import yaml
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.input_segments import InputSegment, InputSegmentInventory
from traust_core.v1.models.operations import AssetRequest, JobResult, WorkerId
from traust_core.v1.models.vocabulary import ActorKind

from traust.context import load
from traust.ops.intake import (
    ExternalValidationInput,
    InventoryDiscoveryMaterializer,
    RescanEventIntakeMaterializer,
    external_validation_input,
)
from traust.ops.router import SecurityRouter

REPO = "https://github.com/example-org/input-only"
PRINCIPAL = Principal(identity="operator@example.com", kind=ActorKind.HUMAN, display="Operator")


def context(tmp_path: Path):
    inputs = tmp_path / "inputs"
    (inputs / "services").mkdir(parents=True)
    (inputs / "services" / "scope-repos.csv").write_text(f"URL\n{REPO}\n", encoding="utf-8")
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump({"home": str(tmp_path / "store"), "locations": {"inputs": str(inputs)}}),
        encoding="utf-8",
    )
    return load(home)


def event_file(tmp_path: Path, *rows: dict[str, object]) -> Path:
    path = tmp_path / "rescan-events.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    return path


def complete(services, order_ids: tuple[str, ...]) -> None:
    worker = WorkerId("test-worker")
    for order_id in order_ids:
        identity = UUID(order_id)
        services.ops.admit(identity)
        assert services.ops.claim(worker, timedelta(minutes=5), order_id=identity) is not None
        services.ops.complete(identity, worker, JobResult.succeeded())


def test_inventory_url_reaches_observation_and_full_audit_orders(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    with core.repository_observation() as observation:
        result = InventoryDiscoveryMaterializer(
            services, observation.query, core.repository_inventory(), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        orders = [services.ops.get(UUID(order_id)) for order_id in result.written]
        repository = services.portfolio.find_repository(REPO)
        assert repository is not None and repository.public is False
        state = observation.query.repo_state(repo_url=REPO)
    assert {(order.asset, order.lane, order.rule) for order in orders} == {
        ("repo_state", None, None),
        ("full_audit", "full-audit", "rule-1-bootstrap"),
    }
    assert state.status == "never-audited"


def test_inventory_discovery_continues_after_malformed_url(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    inventory = InputSegmentInventory(
        segments=(InputSegment(name="test", repository_urls=("https://[::1", REPO)),)
    )
    with core.repository_observation() as observation:
        result = InventoryDiscoveryMaterializer(
            services, observation.query, inventory, PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        orders = [services.ops.get(UUID(order_id)) for order_id in result.written]
    assert result.outcome == "degraded" and result.degraded == {"error": 1}
    assert {order.asset for order in orders} == {"repo_state", "full_audit"}


def test_unconsumed_events_become_distinct_executable_orders(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, core.repository_inventory(), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        events = event_file(
            tmp_path,
            {
                "source": "external-report",
                "repo": REPO,
                "consumed": False,
                "report": "incoming/report.md",
                "targets": "scope/targets.yaml",
            },
            {"source": "cve", "repo": REPO, "consumed": False},
        )
        result = RescanEventIntakeMaterializer(
            services, observation.query, PRINCIPAL, events
        ).materialize(AssetRequest(asset="rescan_event_intake", run_id="event-run"))
        orders = [services.ops.get(UUID(order_id)) for order_id in result.written]
        validation = next(order for order in orders if order.asset == "external_report_validation")
        validation_input = external_validation_input(services.ops.manifest(validation.id))
        state = observation.query.repo_state(repo_url=REPO)
    assert {(order.asset, order.lane, order.event_source) for order in orders} == {
        ("external_report_audit", "full-audit+validate", "external-report"),
        ("external_report_validation", "full-audit+validate", "external-report"),
        ("cve_impact", "impact-lane", "cve"),
    }
    assert validation_input == ExternalValidationInput(
        report="incoming/report.md", targets="scope/targets.yaml"
    )
    assert (
        min(order.priority for order in orders) < SecurityRouter().route(state, (), ())[0].priority
    )


def test_external_reports_remain_separate_while_the_first_is_open(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, core.repository_inventory(), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        events = event_file(
            tmp_path,
            {
                "source": "external-report",
                "repo": REPO,
                "report": "incoming/first-report.md",
                "targets": "scope/first-targets.yaml",
            },
            {
                "source": "external-report",
                "repo": REPO,
                "report": "incoming/second-report.md",
                "targets": "scope/second-targets.yaml",
            },
        )
        intake = RescanEventIntakeMaterializer(services, observation.query, PRINCIPAL, events)
        first = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id="first-run"))
        first_inputs = {
            external_validation_input(services.ops.manifest(UUID(order_id)))
            for order_id in first.written
        }
        complete(services, first.written)
        second = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id="second-run"))
        second_inputs = {
            external_validation_input(services.ops.manifest(UUID(order_id)))
            for order_id in second.written
        }
    assert first.outcome == "degraded" and first.degraded == {"error": 2}
    assert first_inputs == {
        ExternalValidationInput(
            report="incoming/first-report.md", targets="scope/first-targets.yaml"
        )
    }
    assert second.outcome == "succeeded"
    assert second_inputs == {
        ExternalValidationInput(
            report="incoming/second-report.md", targets="scope/second-targets.yaml"
        )
    }
    assert set(first.written).isdisjoint(second.written)


def test_completed_event_is_not_dispatched_again(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, core.repository_inventory(), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        events = event_file(
            tmp_path,
            {
                "source": "external-report",
                "repo": REPO,
                "report": "incoming/report.md",
                "targets": "scope/targets.yaml",
                "consumed": False,
            },
        )
        intake = RescanEventIntakeMaterializer(services, observation.query, PRINCIPAL, events)
        first = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id="first-run"))
        complete(services, first.written)
        repeated = intake.materialize(
            AssetRequest(asset="rescan_event_intake", run_id="repeat-run")
        )
    assert repeated == JobResult.succeeded()
