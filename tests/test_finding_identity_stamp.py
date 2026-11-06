#!/usr/bin/env python3
"""The lane-portable finding-identity stamp (secure-code-audit Step 2b).

The platform's headless worker lanes deny ``python3`` outright and execute
python only through the ``harness-run`` wrapper (scripts under ``/harness``),
so the CLI door — ``python3 -m traust.cli corpus finding-identity
fingerprint <report> --write`` — is unreachable there. Meanwhile the worker
stamps ``metadata.additional.harness_version`` on the report after the
session, and the contracts schema then REQUIRES ``fingerprint`` on every
finding. That combination killed every scan at the platform's gate on the
2026-11-06 dev-cluster E2E bring-up (traust-foundry #10, code fix 1):

    FAIL <repo>-security-audit.json findings/2:
    'fingerprint' is a required property

The skill correctly forbids model-authored identity, so the agent cannot fix
the gap in-session either. These tests pin the contract the fix restores:
the script stamps the report with the one recipe (bit-compatible with what
core admission and SCI compute), the platform's pure-contracts gate accepts
the stamped report, and forged or drifted stamps are refused — never
silently re-identified.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from traust_contracts.paths import schema_dir
from traust_engine.ledger import fingerprint
from traust_engine.reporting.validate import ValidationResult, check_finding_identity

from tests.test_validate_report import _valid_report

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "harnessing"
    / "3-audit"
    / "secure-code-audit"
    / "scripts"
    / "stamp_finding_identity.py"
)

# The recipe's known answers for _valid_report()'s two findings — the same
# vectors traust-ledger's golden suite replays. Bit-compatibility with SCI's
# join keys depends on these exact values.
EXPECTED = (
    "751cd01c845b9a42fbe6ccd09ed16586d183a46216f14527bf36ce7802aa9357",
    "52931d51ade87b6825b3faec555debe756f31403e8c222e6a28b3fdc91e38ae1",
)


def _worker_report():
    """What the platform's worker hands its gate: the skill's report (identity
    never model-authored, so no fingerprints) plus the harness_version the
    worker stamps on it after the session."""
    report = _valid_report()
    for finding in report["findings"]:
        finding.pop("fingerprint", None)
        finding.pop("fingerprint_algo", None)
    report["metadata"].setdefault("additional", {})["harness_version"] = "0.41.0"
    return report


def _gate_errors(report) -> list[str]:
    """The platform worker's pure-contracts gate: jsonschema against the
    installed report.schema.json, resolved exactly as sci-traust-worker.py
    (the packaged ``harness-run reporting validate``) resolves it."""
    directory = schema_dir()
    registry = Registry()
    for schema_file in sorted(directory.glob("*.schema.json")):
        document = json.loads(schema_file.read_text(encoding="utf-8"))
        registry = registry.with_resource(
            document.get("$id", schema_file.name), Resource.from_contents(document)
        )
    schema = json.loads((directory / "report.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
    return [error.message for error in validator.iter_errors(report)]


def _run_script(path: Path, *extra: str) -> subprocess.CompletedProcess:
    # -I mirrors the harness-run wrapper, which execs the venv interpreter in
    # isolated mode (no PYTHON* env, no user site, no script-dir sys.path).
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), str(path), *extra],
        capture_output=True,
        text=True,
        check=False,
    )


def _write_report(tmp_path: Path, report) -> Path:
    path = tmp_path / "widget-security-audit.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path


def test_unstamped_versioned_report_fails_the_platform_gate(tmp_path):
    """The live failure, reproduced: the worker's harness_version stamp arms
    the schema's fingerprint requirement, and the skill's (correctly)
    unstamped report dies at the pure-contracts gate."""
    errors = _gate_errors(_worker_report())
    assert errors, "an unstamped harness-versioned report must fail the gate"
    missing = [e for e in errors if "'fingerprint' is a required property" in e]
    assert missing, errors


def test_stamp_makes_the_report_pass_the_platform_gate(tmp_path):
    path = _write_report(tmp_path, _worker_report())
    done = _run_script(path)
    assert done.returncode == 0, done.stderr

    report = json.loads(path.read_text(encoding="utf-8"))
    repo = report["metadata"]["repository"]
    for finding, expected in zip(report["findings"], EXPECTED, strict=True):
        assert finding["fingerprint"] == expected
        assert finding["fingerprint"] == fingerprint(finding, repo)
        assert finding["fingerprint_algo"] == "v3"
    assert _gate_errors(report) == [], "the stamped report must pass the gate"


def test_stamp_satisfies_the_harness_identity_check(tmp_path):
    """The dev lane's gate (traust reporting validate) recomputes every stamp;
    the script's output must be silent under it too."""
    path = _write_report(tmp_path, _worker_report())
    assert _run_script(path).returncode == 0

    report = json.loads(path.read_text(encoding="utf-8"))
    result = ValidationResult(str(path))
    check_finding_identity(report, result)
    assert not result.errors, result.errors


def test_stamp_is_idempotent(tmp_path):
    path = _write_report(tmp_path, _worker_report())
    assert _run_script(path).returncode == 0
    stamped = path.read_text(encoding="utf-8")

    again = _run_script(path)
    assert again.returncode == 0, again.stderr
    assert "0 field(s) written" in again.stdout
    assert path.read_text(encoding="utf-8") == stamped


def test_a_moved_identity_is_refused_and_named(tmp_path):
    """A stamp the recipe did not mint (here: single-character tamper) is an
    error, not a silent re-identification — ledger events key on these
    values."""
    path = _write_report(tmp_path, _worker_report())
    assert _run_script(path).returncode == 0
    report = json.loads(path.read_text(encoding="utf-8"))
    fp = report["findings"][0]["fingerprint"]
    report["findings"][0]["fingerprint"] = ("b" if fp[0] != "b" else "c") + fp[1:]
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    refused = _run_script(path)
    assert refused.returncode == 1, refused.stdout
    assert "refusing to move" in refused.stderr
    assert report["findings"][0]["id"] in refused.stderr

    # The in-session re-stamp escape hatch: an unrecorded report has nothing
    # referencing its stamps yet.
    moved = _run_script(path, "--allow-identity-move")
    assert moved.returncode == 0, moved.stderr
    restored = json.loads(path.read_text(encoding="utf-8"))
    assert restored["findings"][0]["fingerprint"] == fp


def test_usage_and_missing_file_fail_closed(tmp_path):
    assert _run_script(tmp_path / "nope.json").returncode == 2
    bad = _run_script(tmp_path, "--nonsense")
    assert bad.returncode == 2
    assert "usage:" in bad.stderr
