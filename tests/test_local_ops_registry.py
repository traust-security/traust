"""Bootstrap the real local rig and resolve its routing through core's catalog."""

from __future__ import annotations

from pathlib import Path

import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.providers.model_catalog import ModelCatalog

from tests.local_ops_support import LocalOpsRig


def _catalog(rig: LocalOpsRig) -> ModelCatalog:
    core = Context(Config.from_home(rig.config_home))
    core.register_model_catalog(rig.config_home / "model-registry.yaml")
    assert core.model_catalog is not None
    assert core.model_catalog.validate() == []
    return core.model_catalog


def test_fresh_up_refloors_before_the_real_installer_and_keeps_operator_edits(
    tmp_path: Path,
) -> None:
    rig = LocalOpsRig(tmp_path)
    source = rig.root / "config/model-registry.yaml"
    shipped = source.read_bytes()
    shipped_roles = yaml.safe_load(shipped)["roles"]
    assert not rig.config_home.exists()

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert (rig.config_home / "traust.yaml").is_file()
    catalog = _catalog(rig)
    deep_audit = catalog.resolve_role("deep-audit")
    assert catalog.resolve(deep_audit).tier == "opus-class"
    for name, role in shipped_roles.items():
        if role["floor"] == "mythos-class":
            assert catalog.resolve(catalog.resolve_role(name)).tier == "opus-class"
    assert source.read_bytes() == shipped

    # Restore shipped routing as a substantive operator edit, preserving even
    # its comments and line endings rather than rewriting equivalent YAML.
    operator_registry = b"# Operator restored shipped routing.\r\n" + shipped
    installed = rig.config_home / "model-registry.yaml"
    installed.write_bytes(operator_registry)

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert installed.read_bytes() == operator_registry
    catalog = _catalog(rig)
    assert catalog.resolve(catalog.resolve_role("deep-audit")).tier == "mythos-class"
    assert source.read_bytes() == shipped


def test_fresh_config_keeps_an_existing_operator_registry(tmp_path: Path) -> None:
    rig = LocalOpsRig(tmp_path)
    source = rig.root / "config/model-registry.yaml"
    shipped = source.read_bytes()
    operator_registry = b"# Operator-managed registry; do not regenerate.\r\n" + shipped
    rig.config_home.mkdir(parents=True)
    installed = rig.config_home / "model-registry.yaml"
    installed.write_bytes(operator_registry)
    assert not (rig.config_home / "traust.yaml").exists()

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert (rig.config_home / "traust.yaml").is_file()
    assert installed.read_bytes() == operator_registry
    catalog = _catalog(rig)
    assert catalog.resolve(catalog.resolve_role("deep-audit")).tier == "mythos-class"
    assert source.read_bytes() == shipped


def test_refloor_follows_shipped_approved_tier_metadata(tmp_path: Path) -> None:
    rig = LocalOpsRig(tmp_path)
    source = rig.root / "config/model-registry.yaml"
    registry = yaml.safe_load(source.read_bytes())
    renamed = {}
    for provider in registry["providers"].values():
        for name, model in list(provider["models"].items()):
            if model["tier"] == "opus-class":
                replacement = f"rig-test-model-{len(renamed)}"
                renamed[name] = replacement
                provider["models"][replacement] = provider["models"].pop(name)
    assert renamed
    for role in registry["roles"].values():
        for field in ("approved", "candidates"):
            role[field] = [renamed.get(name, name) for name in role[field]]
    source.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
    modified_source = source.read_bytes()

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    catalog = _catalog(rig)
    resolved = catalog.resolve_role("deep-audit")
    assert resolved in renamed.values()
    assert catalog.resolve(resolved).tier == "opus-class"
    assert source.read_bytes() == modified_source


def test_up_fails_without_an_approved_opus_model_instead_of_seeding_fallback(
    tmp_path: Path,
) -> None:
    rig = LocalOpsRig(tmp_path)
    source = rig.root / "config/model-registry.yaml"
    registry = yaml.safe_load(source.read_bytes())
    opus_models = {
        name
        for provider in registry["providers"].values()
        for name, model in provider["models"].items()
        if model["tier"] == "opus-class"
    }
    assert opus_models
    for role in registry["roles"].values():
        removed = [name for name in role["approved"] if name in opus_models]
        role["approved"] = [name for name in role["approved"] if name not in opus_models]
        role["candidates"].extend(removed)
    source.write_text(yaml.safe_dump(registry, sort_keys=False), encoding="utf-8")
    modified_source = source.read_bytes()

    result = rig.run("up")

    assert result.returncode != 0
    assert "opus-class" in result.stderr
    assert not (rig.config_home / "model-registry.yaml").exists()
    assert not (rig.config_home / "traust.yaml").exists()
    assert source.read_bytes() == modified_source


def test_up_creates_the_events_file_empty_and_keeps_what_an_operator_appended(
    tmp_path: Path,
) -> None:
    rig = LocalOpsRig(tmp_path)
    assert rig.run("up").returncode == 0
    events = rig.root / ".local-ops" / "run" / "analysis-results" / "findings" / "_manifest"
    events /= "rescan-events.jsonl"
    assert events.read_text() == ""
    events.write_text('{"source": "cve", "repo": "https://github.com/org/repo"}\n')
    result = rig.run("up")
    assert result.returncode == 0, result.stdout + result.stderr
    assert events.read_text() == '{"source": "cve", "repo": "https://github.com/org/repo"}\n'


def test_up_creates_the_events_file_where_the_rig_configures_its_results(
    tmp_path: Path,
) -> None:
    """An operator may point the rig's analysis_results elsewhere; the file the intake
    needs belongs there, not under the path a fresh rig would have configured."""
    rig = LocalOpsRig(tmp_path)
    assert rig.run("up").returncode == 0
    custom = tmp_path / "elsewhere"
    installed = rig.config_home / "traust.yaml"
    document = yaml.safe_load(installed.read_text())
    document["locations"]["analysis_results"] = str(custom)
    installed.write_text(yaml.safe_dump(document, sort_keys=False))
    events = custom / "findings" / "_manifest" / "rescan-events.jsonl"

    result = rig.run("up")

    assert result.returncode == 0, result.stdout + result.stderr
    assert events.is_file()


def test_up_fails_loudly_on_a_config_that_cannot_be_read(tmp_path: Path) -> None:
    """A corrupt traust.yaml must not produce a silent success with the events file created
    under some default tree (the resolver the intake uses fails, and so does up)."""
    rig = LocalOpsRig(tmp_path)
    assert rig.run("up").returncode == 0
    installed = rig.config_home / "traust.yaml"
    installed.write_text("locations: [not, a, mapping")

    result = rig.run("up")

    assert result.returncode != 0


def test_the_doctor_compares_the_volume_with_the_rigs_birth_not_its_activity(
    tmp_path: Path,
) -> None:
    """Artifact activity must not read as a reset: the volume's age is compared with the
    rig's birth marker, not the artifacts directory's mtime (which every landing moves)."""
    import os
    from datetime import UTC, datetime

    rig = LocalOpsRig(tmp_path)
    assert rig.run("up").returncode == 0
    marker = rig.root / ".local-ops" / "run" / ".artifacts-created"
    assert marker.is_file()
    born = marker.stat().st_mtime
    artifacts = rig.root / ".local-ops" / "run" / "artifacts"
    artifacts.mkdir()
    (artifacts / "payload").write_bytes(b"x")
    os.utime(artifacts, (born - 90 * 86400, born - 90 * 86400))  # a landing 90 days later

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    # Podman prints "YYYY-MM-DD HH:MM:SS +00:00 UTC"; Docker prints RFC3339 with no space.
    for created in (f"{today} 00:00:00 +00:00 UTC", f"{today}T12:00:00Z"):
        agree = rig.run("doctor", env={"OPS_FAKE_VOLUME_CREATED": created})
        assert "disagree in age" not in agree.stderr, created
    stale = rig.run("doctor", env={"OPS_FAKE_VOLUME_CREATED": "2019-01-01T00:00:00Z"})
    assert "disagree in age" in stale.stderr
