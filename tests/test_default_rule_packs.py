"""A default traust run uses the rule packs the security pack ships.

The opengrep rule pack and gitleaks config live only in packs/security/.
Nothing in a deployment configures
them: the adopter-style fixture config home below sets no rule-pack location,
and a plain `traust adapters …` run must still report recent rules. If the
default ever resolves somewhere stale, these fail. Not marked `integration`,
so the pre-push hook runs them wherever opengrep and gitleaks are installed.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "config"
JWT_CANARY = (
    "import jwt\n\n\n"
    "def read(token):\n"
    '    return jwt.decode(token, options={"verify_signature": False})\n'
)


def _run(*args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "TRAUST_CONFIG_HOME": str(FIXTURE_CONFIG)}
    return subprocess.run(
        [sys.executable, "-m", "traust.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_fixture_config_sets_no_rule_pack_location():
    locations = FIXTURE_CONFIG / "traust.yaml"
    text = locations.read_text(encoding="utf-8") if locations.is_file() else ""
    assert "opengrep_rules" not in text and "gitleaks_config" not in text


@pytest.mark.skipif(not shutil.which("opengrep"), reason="opengrep not on PATH")
def test_default_opengrep_run_reports_a_current_rule(tmp_path):
    (tmp_path / "app.py").write_text(JWT_CANARY, encoding="utf-8")
    out = tmp_path / "facts.json"
    proc = _run("adapters", "opengrep", str(tmp_path), "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert "traust-python-authentication-jwt-signature-unverified" in {
        f["rule_id"] for f in report["facts"]
    }
    assert any(
        "packs/security/detection/opengrep-rules" in p
        for r in report["rules"]
        for p in r.get("config_paths", [])
    )


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not on PATH")
def test_default_gitleaks_run_reports_a_traust_detector(tmp_path):
    (tmp_path / "settings.py").write_text('TOKEN = "sha256~' + "B" * 43 + '"\n', encoding="utf-8")
    out = tmp_path / "candidates.json"
    proc = _run("adapters", "gitleaks", "--repo", str(tmp_path), "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert "traust-openshift-sha256-token" in {c["rule_id"] for c in report["candidates"]}


@pytest.mark.skipif(not shutil.which("opengrep"), reason="opengrep not on PATH")
def test_target_nosem_comment_does_not_hide_a_fact(tmp_path):
    marked = JWT_CANARY.replace("False})\n", "False})  # nosemgrep\n")
    (tmp_path / "app.py").write_text(marked, encoding="utf-8")
    out = tmp_path / "facts.json"
    proc = _run("adapters", "opengrep", str(tmp_path), "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    facts = json.loads(out.read_text(encoding="utf-8"))["facts"]
    hits = [
        f for f in facts if f["rule_id"] == "traust-python-authentication-jwt-signature-unverified"
    ]
    assert hits and all(f["nosem_marked"] for f in hits)
