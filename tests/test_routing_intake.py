from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    AssetRequest,
    JobResult,
    OrderReason,
    OrderState,
    WorkerId,
)
from traust_core.v1.models.vocabulary import ActorKind

from traust.cli import portfolio_observe
from traust.context import inputs_dir, load
from traust.inventory import InputSegment, InputSegmentInventory, repository_inventory
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
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
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
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
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
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
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
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
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


def test_rejected_inventory_entries_do_not_publish_private_urls(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    core = context(tmp_path)
    services = core.services()
    username, password = "private-person-canary", "private-password-canary"
    rejected = f"https://{username}:{password}@github.com/example/repo"
    inventory = InputSegmentInventory(
        segments=(InputSegment(name="probe", repository_urls=(rejected, "https://[::1", REPO)),)
    )
    with core.repository_observation() as observation:
        result = InventoryDiscoveryMaterializer(
            services, observation.query, inventory, PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="privacy-run"))
    assert result.outcome == "degraded" and result.degraded == {"error": 2}
    assert {services.ops.get(UUID(value)).asset for value in result.written} == {
        "repo_state",
        "full_audit",
    }
    assert username not in caplog.text
    assert password not in caplog.text
    assert rejected not in caplog.text


def test_inventory_failure_diagnostics_do_not_echo_provider_exception_payloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    core = context(tmp_path)
    services = core.services()
    private = "private-provider-canary:private-provider-password"

    def refused(*args, **kwargs):
        raise ValidationError(private)

    monkeypatch.setattr(services.portfolio, "find_repository", refused)
    with core.repository_observation() as observation:
        result = InventoryDiscoveryMaterializer(
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="provider-failure"))
    assert result.outcome == "degraded" and result.degraded == {"error": 1}
    assert not result.written
    assert private not in caplog.text


@pytest.mark.parametrize("failed_asset", ["external_report_audit", "external_report_validation"])
@pytest.mark.parametrize(
    "outcome",
    [
        JobResult.failed(OrderReason.RUNNER_CRASHED),
        JobResult.refused(OrderReason.SOURCE_UNAVAILABLE),
    ],
    ids=["failed", "refused"],
)
def test_unsuccessful_event_work_stays_visible_until_operator_archives_it(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    failed_asset: str,
    outcome: JobResult,
) -> None:
    core = context(tmp_path)
    services = core.services()
    row = {
        "source": "external-report",
        "repo": REPO,
        "report": "incoming/report.md",
        "targets": "scope/targets.yaml",
    }
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        events = event_file(tmp_path, row)
        intake = RescanEventIntakeMaterializer(services, observation.query, PRINCIPAL, events)
        first = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id="first"))
        worker = WorkerId("failure-worker")
        unsuccessful = None
        for value in first.written:
            order = services.ops.get(UUID(value))
            services.ops.admit(order.id)
            assert services.ops.claim(worker, timedelta(minutes=5), order_id=order.id) is not None
            result = outcome if order.asset == failed_asset else JobResult.succeeded()
            services.ops.complete(order.id, worker, result)
            if order.asset == failed_asset:
                unsuccessful = order.id
        assert unsuccessful is not None
        for run_id in ("next-tick", "later-tick"):
            repeated = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id=run_id))
            assert repeated.outcome == "degraded" and repeated.degraded == {"error": 1}
            assert not repeated.written
        assert str(unsuccessful) in caplog.text
        event_file(tmp_path, {**row, "consumed": True})
        archived = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id="archived"))
    assert archived == JobResult.succeeded()
    assert services.ops.get(unsuccessful).state == OrderState(outcome.outcome)


def test_many_events_read_each_groups_history_and_manifests_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = context(tmp_path)
    services = core.services()
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        for index in range(5):
            events = event_file(tmp_path, {"source": "cve", "repo": REPO, "note": f"old-{index}"})
            intake = RescanEventIntakeMaterializer(services, observation.query, PRINCIPAL, events)
            seeded = intake.materialize(AssetRequest(asset="rescan_event_intake", run_id="seed"))
            complete(services, seeded.written)
        events = event_file(
            tmp_path, *({"source": "cve", "repo": REPO, "note": f"new-{i}"} for i in range(20))
        )
        counts = {"history": 0, "manifests": 0}
        original_list, original_manifest = services.ops.list, services.ops.manifest

        def history(*args, **kwargs):
            counts["history"] += 1
            return original_list(*args, **kwargs)

        def manifest(*args, **kwargs):
            counts["manifests"] += 1
            return original_manifest(*args, **kwargs)

        monkeypatch.setattr(services.ops, "list", history)
        monkeypatch.setattr(services.ops, "manifest", manifest)
        result = RescanEventIntakeMaterializer(
            services, observation.query, PRINCIPAL, events
        ).materialize(AssetRequest(asset="rescan_event_intake", run_id="many"))
    assert result.outcome == "degraded" and result.degraded == {"error": 19}
    assert len(result.written) == 1
    assert counts == {"history": 1, "manifests": 6}
    assert services.ops.get(UUID(result.written[0])).state == OrderState.PLANNED


def test_duplicate_feed_rows_share_the_same_in_tick_event_binding(tmp_path: Path) -> None:
    core = context(tmp_path)
    services = core.services()
    row = {
        "source": "external-report",
        "repo": REPO,
        "report": "incoming/one-report.md",
        "targets": "scope/targets.yaml",
    }
    with core.repository_observation() as observation:
        InventoryDiscoveryMaterializer(
            services, observation.query, repository_inventory(inputs_dir(core)), PRINCIPAL
        ).materialize(AssetRequest(asset="inventory_discovery", run_id="inventory-run"))
        events = event_file(tmp_path, row, row, row)
        result = RescanEventIntakeMaterializer(
            services, observation.query, PRINCIPAL, events
        ).materialize(AssetRequest(asset="rescan_event_intake", run_id="duplicates"))
    assert result.outcome == "succeeded"
    assert {services.ops.get(UUID(value)).asset for value in result.written} == {
        "external_report_audit",
        "external_report_validation",
    }
    assert len(result.written) == 2


def test_inventory_cli_rejects_provider_errors_without_private_tracebacks(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    context(tmp_path)
    username, password = "private-cli-person", "private-cli-password"
    rejected = f"https://{username}:{password}@github.com/example/rejected"
    (tmp_path / "inputs" / "services" / "scope-repos.csv").write_text(
        f"URL\n{rejected}\n{REPO}\n", encoding="utf-8"
    )
    code = portfolio_observe.inventory_discover(
        ["--config-home", str(tmp_path / "config"), "--run-id", "cli-privacy"]
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert code != 0
    assert result["outcome"] == "failed" and result["reason"] == "bad_request"
    assert not result["written"]
    diagnostics = captured.err + caplog.text
    assert username not in diagnostics and password not in diagnostics
    assert rejected not in diagnostics and "Traceback" not in diagnostics


@pytest.mark.parametrize("present", [False, True], ids=["missing", "empty"])
def test_a_missing_events_file_is_refused_and_an_empty_one_is_no_events(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, present: bool
) -> None:
    core = context(tmp_path)
    events = tmp_path / "rescan-events.jsonl"
    if present:
        events.write_text("", encoding="utf-8")
    with core.repository_observation() as observation:
        intake = RescanEventIntakeMaterializer(
            core.services(), observation.query, PRINCIPAL, events
        )
        with caplog.at_level(logging.WARNING, logger="traust.ops.intake"):
            result = intake.materialize(
                AssetRequest(asset="rescan_event_intake", run_id="events-run")
            )
    if present:
        assert result == JobResult.succeeded()
    else:
        assert result == JobResult.failed(OrderReason.BAD_REQUEST)
        assert "no rescan-events file rescan-events.jsonl" in caplog.text
        assert str(tmp_path) not in caplog.text
