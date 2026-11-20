from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not shutil.which("opengrep"), reason="native Opengrep integration")


def rule_pack(root: Path, rule_id: str = "acme.custom.rule") -> Path:
    root.mkdir()
    (root / "policy.yaml").write_text(
        "rules:\n  - id: " + rule_id + "\n    languages: [python]\n"
        "    severity: ERROR\n    message: Untrusted operation\n"
        "    metadata:\n      cwe: [CWE-78]\n    pattern: acme_unsafe($X)\n"
    )
    (root / "policy.py").write_text(
        "# ruleid: " + rule_id + "\nacme_unsafe(value)\n# ok: " + rule_id + "\nacme_safe(value)\n"
    )
    return root


def environment(tmp_path: Path, overrides: dict | None = None) -> tuple[Path, dict[str, str]]:
    home = tmp_path / "config"
    home.mkdir()
    config = {"home": str(tmp_path / "store"), **(overrides or {})}
    (home / "traust.yaml").write_text(json.dumps(config))
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR")
    }
    env.update({"TRAUST_CONFIG_HOME": str(home), "XDG_CACHE_HOME": str(tmp_path / "cache")})
    return home, env


def run_cli(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "traust.cli", *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_native_quality_cli_passes_real_positive_and_negative_cases_without_a_database(
    tmp_path: Path,
) -> None:
    pack = rule_pack(tmp_path / "rules")
    _, env = environment(tmp_path)
    result = run_cli(env, "sweep", "check-rules", str(pack))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["passed"] is True
    assert report["rules"] == ["acme.custom.rule"]
    assert {check["name"] for check in report["checks"]} == {"validate", "test"}
    assert not (tmp_path / "store" / "traust.db").exists()


@pytest.mark.parametrize("failure", ["missing-negative", "unexpected-match", "no-tests"])
def test_quality_cli_refuses_incomplete_or_incorrect_behavior_cases(
    tmp_path: Path, failure: str
) -> None:
    pack = rule_pack(tmp_path / "rules")
    fixture = pack / "policy.py"
    if failure == "missing-negative":
        fixture.write_text("# ruleid: acme.custom.rule\nacme_unsafe(value)\n")
    elif failure == "unexpected-match":
        fixture.write_text(fixture.read_text() + "acme_unsafe(other)\n")
    else:
        fixture.unlink()
    _, env = environment(tmp_path)
    result = run_cli(env, "sweep", "check-rules", str(pack))
    assert result.returncode == 1, result.stderr
    report = json.loads(result.stdout)
    assert report["passed"] is False
    assert any(check["name"] == "test" and not check["passed"] for check in report["checks"])


def test_configured_adopter_pack_is_additive_and_resolves_beside_the_allowlist(
    tmp_path: Path,
) -> None:
    rule_pack(tmp_path / "custom-rules")
    home, env = environment(
        tmp_path, {"overrides": {"rule_pack_allowlist": str(tmp_path / "config" / "rules.yaml")}}
    )
    (home / "rules.yaml").write_text(
        "packs:\n  acme:\n    enabled: true\n    source: ../custom-rules\n"
        "    rules: [acme.custom.rule]\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("acme_unsafe(request_value)\nacme_safe(request_value)\n")
    output = tmp_path / "facts.json"
    result = run_cli(env, "adapters", "opengrep", str(target), "--out", str(output))
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert "acme.custom.rule" in {fact["rule_id"] for fact in report["facts"]}
    assert report["supplemental_packs"]["applied"] == ["acme"]
    assert any(source["source"] == "traust rule pack" for source in report["rules"])
    assert all(check["passed"] for check in report["quality_checks"])


def test_invalid_enabled_adopter_pack_refuses_the_scan_instead_of_losing_coverage(
    tmp_path: Path,
) -> None:
    pack = rule_pack(tmp_path / "custom-rules")
    (pack / "policy.py").unlink()
    home, env = environment(
        tmp_path, {"overrides": {"rule_pack_allowlist": str(tmp_path / "config" / "rules.yaml")}}
    )
    (home / "rules.yaml").write_text(
        "packs:\n  acme:\n    enabled: true\n    source: ../custom-rules\n"
        "    rules: [acme.custom.rule]\n"
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("acme_unsafe(value)\n")
    output = tmp_path / "facts.json"
    result = run_cli(env, "adapters", "opengrep", str(target), "--out", str(output))
    assert result.returncode != 0
    assert not output.exists()


def test_intake_and_runtime_use_the_same_gate_and_keep_the_configured_addition(
    tmp_path: Path,
) -> None:
    rule_pack(tmp_path / "adopter", "example.adopter")
    valid = rule_pack(tmp_path / "valid", "example.runtime")
    invalid = rule_pack(tmp_path / "invalid", "example.untested")
    (invalid / "policy.py").unlink()
    _, env = environment(tmp_path, {"locations": {"opengrep_adopter_rules": "../adopter"}})

    destination = tmp_path / "refused-pack"
    intake = run_cli(
        env, "sweep", "intake-rules", str(valid), str(invalid), "--into", str(destination)
    )
    assert intake.returncode == 1, intake.stderr
    verdict = json.loads(intake.stdout)
    assert verdict["admitted"] is False
    assert verdict["applied"] == []
    assert "destination" not in verdict
    assert not destination.exists()
    assert "example.untested" in {r["rule_id"] for r in verdict["refused"]}
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("acme_unsafe(value)\nacme_safe(value)\n")
    output = tmp_path / "facts.json"
    scan = run_cli(
        env,
        "adapters",
        "opengrep",
        str(target),
        "--out",
        str(output),
        "--add-rules",
        str(valid),
        "--add-rules",
        str(invalid),
    )
    assert scan.returncode == 0, scan.stderr
    report = json.loads(output.read_text())
    assert report["outcome"] == "degraded"
    assert "example.untested" in {
        receipt["rule_id"] for receipt in report["additive_rules"]["refused"]
    }
    assert {f["rule_id"] for f in report["facts"] if f["origin"].startswith("additive:")} == {
        "example.adopter",
        "example.runtime",
    }


def test_native_intake_publishes_multiple_sources_then_scans_the_accepted_bytes(
    tmp_path: Path,
) -> None:
    first = rule_pack(tmp_path / "first", "example.first")
    second = rule_pack(tmp_path / "second", "example.second")
    _, env = environment(tmp_path)
    destination = tmp_path / "accepted"
    intake = run_cli(
        env, "sweep", "intake-rules", str(first), str(second), "--into", str(destination)
    )
    assert intake.returncode == 0, intake.stderr
    verdict = json.loads(intake.stdout)
    assert verdict["admitted"] is True
    assert Path(verdict["destination"]) == destination
    assert verdict["refused"] == []
    assert {check["name"] for check in verdict["quality_checks"]} == {"validate", "test"}
    assert all(check["passed"] for check in verdict["quality_checks"])
    assert len(list(destination.rglob("policy.yaml"))) == 2
    assert len(list(destination.rglob("policy.py"))) == 2
    shutil.rmtree(first)
    shutil.rmtree(second)
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("acme_unsafe(value)\nacme_safe(value)\n")
    output = tmp_path / "facts.json"
    scan = run_cli(
        env, "adapters", "opengrep", str(target), "--add-rules", str(destination),
        "--out", str(output),
    )
    assert scan.returncode == 0, scan.stderr
    report = json.loads(output.read_text())
    assert {"example.first", "example.second"} <= {
        fact["rule_id"] for fact in report["facts"]
    }
    assert not (tmp_path / "store" / "traust.db").exists()


@pytest.mark.parametrize(
    "failure", ["invalid-schema", "missing-negative", "unexpected-match", "no-tests"]
)
def test_native_intake_refuses_before_publishing(tmp_path: Path, failure: str) -> None:
    source = rule_pack(tmp_path / "private")
    fixture = source / "policy.py"
    if failure == "invalid-schema":
        rule = source / "policy.yaml"
        rule.write_text(rule.read_text().replace("    pattern:", "    unknown-pattern:"))
    elif failure == "missing-negative":
        fixture.write_text("# ruleid: acme.custom.rule\nacme_unsafe(value)\n")
    elif failure == "unexpected-match":
        fixture.write_text(fixture.read_text() + "acme_unsafe(other)\n")
    else:
        fixture.unlink()
    _, env = environment(tmp_path)
    destination = tmp_path / "accepted"
    result = run_cli(
        env, "sweep", "intake-rules", str(source), "--into", str(destination)
    )
    assert result.returncode == 1, result.stderr
    verdict = json.loads(result.stdout)
    assert verdict["admitted"] is False
    assert verdict["applied"] == []
    assert verdict["refused"]
    assert "destination" not in verdict
    assert not destination.exists()
    assert not (tmp_path / "store" / "traust.db").exists()


def test_native_intake_never_overwrites_an_existing_destination(tmp_path: Path) -> None:
    source = rule_pack(tmp_path / "private")
    _, env = environment(tmp_path)
    destination = tmp_path / "installed"
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_bytes(b"installed bytes\n")
    result = run_cli(
        env, "sweep", "intake-rules", str(source), "--into", str(destination)
    )
    assert result.returncode in (1, 2), result.stdout
    assert list(destination.iterdir()) == [marker]
    assert marker.read_bytes() == b"installed bytes\n"
