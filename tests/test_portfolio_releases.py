from __future__ import annotations

import csv
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from traust_core.v1.context import Config, Context, Locations
from traust_core.v1.errors import ConfigError, ValidationError
from traust_core.v1.models.release_inventory import ReleaseArtifactKind, ReleaseObservation

from traust.cli import portfolio_releases
from traust.cli.portfolio_releases import write_batch
from traust.release_config import read_release_watch, register_release_inventory


def test_rpm_batch_pins_the_observed_commit_instead_of_a_default_branch(tmp_path: Path) -> None:
    path = tmp_path / "rpm.csv"
    observation = ReleaseObservation(
        key="observed-rpm",
        kind=ReleaseArtifactKind.RPM,
        target="https://gitlab.com/example/rpms/package",
        head="a" * 40,
    )
    write_batch(path, ReleaseArtifactKind.RPM, (observation,), tmp_path)
    with path.open(newline="") as stream:
        [row] = list(csv.DictReader(stream))
    assert row["GitLab URL"] == observation.target
    assert row["Branch"] == "commit:" + "a" * 40
    assert row["Component"] == "package"
    with pytest.raises(ValidationError):
        write_batch(
            path,
            ReleaseArtifactKind.RPM,
            (observation.model_copy(update={"head": None}),),
            tmp_path,
        )


def test_container_batch_retains_image_identity_and_inventory_key_context(tmp_path: Path) -> None:
    path = tmp_path / "images.csv"
    observation = ReleaseObservation(
        key="observed-image",
        kind=ReleaseArtifactKind.CONTAINER,
        target="manager",
        repository="https://github.com/example/source",
        inventory="catalog/operator/1.1/operator-1.1-payload-repos.csv",
    )
    write_batch(path, ReleaseArtifactKind.CONTAINER, (observation,), tmp_path / "inputs")
    with path.open(newline="") as stream:
        [row] = list(csv.DictReader(stream))
    assert row == {
        "Payload Image Key(s)": "manager",
        "GitHub URL": observation.repository,
        "Inventory Source": str(tmp_path / "inputs" / observation.inventory),
    }


def test_artifact_audit_runs_the_existing_skill_adapter_with_exact_order_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order_id = uuid4()
    observation = ReleaseObservation(
        key="observed-image",
        kind=ReleaseArtifactKind.CONTAINER,
        target="quay.io/example/application@sha256:abc",
        inventory="payload-1.1-payload-repos.csv",
    )
    calls = []

    def targets(kind: ReleaseArtifactKind, selected: object) -> tuple[ReleaseObservation, ...]:
        assert kind == ReleaseArtifactKind.CONTAINER and selected == order_id
        return (observation,)

    core = SimpleNamespace(
        services=lambda: SimpleNamespace(releases=SimpleNamespace(targets=targets))
    )
    monkeypatch.setattr(portfolio_releases, "load", lambda _: core)
    monkeypatch.setattr(portfolio_releases, "inputs_dir", lambda _: tmp_path)

    def run(argv: list[str]) -> int:
        calls.append(argv)
        with Path(argv[argv.index("--repo") + 1]).open(newline="") as stream:
            [row] = list(csv.DictReader(stream))
        assert row["Payload Image Key(s)"] == observation.target
        return 4

    monkeypatch.setattr("traust.cli.session.run", run)
    result = portfolio_releases.audit(
        ["--kind", "container", "--role", "deep-audit", "--run-id", str(order_id)]
    )
    assert result == 4
    [command] = calls
    assert command[:4] == ["--skill", "secure-container-audit", "--role", "deep-audit"]
    assert "--checkout" not in command
    assert command[command.index("--run-id") + 1] == str(order_id)


def test_watch_config_preserves_explicit_product_binding_and_empty_baseline(tmp_path: Path) -> None:
    path = tmp_path / "rpm-distgit-watch.yaml"
    assert read_release_watch(path).active == ()
    path.write_text(
        'active: ["https://gitlab.com/example/rpms/package"]\n'
        'products: {"payload-{V}-payload-repos.csv": application}\n'
    )
    watch = read_release_watch(path)
    assert watch.active == ("https://gitlab.com/example/rpms/package",)
    assert watch.products == {"payload-{V}-payload-repos.csv": "application"}


def test_release_registration_does_not_require_inventory_in_zero_setup_mode(tmp_path: Path) -> None:
    core = Context(Config(home=tmp_path / "home"))
    register_release_inventory(core, tmp_path)
    assert "release-inventory" not in core.feeds.names()


def test_explicit_nonlocal_inventory_is_not_silently_ignored(tmp_path: Path) -> None:
    core = Context(
        Config(home=tmp_path / "home", locations=Locations(inputs="s3://example-bucket/inputs"))
    )
    with pytest.raises(ConfigError):
        register_release_inventory(core, tmp_path)
