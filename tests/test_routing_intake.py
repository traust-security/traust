from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import yaml
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import AssetRequest
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


def test_unconsumed_events_become_distinct_executable_orders(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, core.repository_inventory(), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        events = tmp_path / "rescan-events.jsonl"
        events.write_text(
            "\n".join(
                json.dumps(
                    {
                        "source": source,
                        "repo": REPO,
                        "consumed": False,
                        **(
                            {"report": "incoming/report.md", "targets": "scope/targets.yaml"}
                            if source == "external-report"
                            else {}
                        ),
                    }
                )
                for source in ("external-report", "cve")
            ),
            encoding="utf-8",
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
