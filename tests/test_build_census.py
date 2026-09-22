"""Tests for harnessing/census/scripts/build_census.py — the corpus census."""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from traust.context import load_engine
from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "build_census", skill_dir("census") / "scripts" / "build_census.py"
)
bc = importlib.util.module_from_spec(_SPEC)
sys.modules["build_census"] = bc
_SPEC.loader.exec_module(bc)

LIVE_ROOT = _ROOT.parent / "analysis-results"

CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: Example}
  oss-findings: {label: upstream-oss, ownership: upstream, business_unit: OSS}
engagements:
  contoso:
    label: contoso
    ownership: external-bu
    business_unit: Contoso
    tree: contoso-findings
    status: registered
"""


def _report(repo_url, findings):
    return {"metadata": {"repository": repo_url}, "findings": findings}


def _finding(fid, sev, fp, validation_status=None):
    f = {
        "id": fid,
        "severity": sev,
        "fingerprint": fp,
        "cwes": ["CWE-287"],
        "locations": [{"path": "pkg/a.go"}],
    }
    if validation_status:
        f["validation_status"] = validation_status
    return f


def _write(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def workspace(tmp_path):
    cfg_path = tmp_path / "corpus-config.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    ar = tmp_path / "analysis-results"

    # repo1 (owned, HEAD): plain audit — 1 vuln, 1 hardening, 1 FP
    _write(
        ar / "findings/prodA/repo1/repo1-security-audit.json",
        _report(
            "https://github.com/org/repo1",
            [
                _finding("R1-001", "high", "fp-r1-vuln"),
                _finding("R1-002", "medium", "fp-r1-hard", validation_status="hardening"),
                _finding("R1-003", "high", "fp-r1-fp", validation_status="false_positive"),
            ],
        ),
    )
    # repo1 branch re-audit: one confirmation of HEAD + one branch-only
    _write(
        ar / "findings/prodA/repo1__release-4.19/repo1__release-4.19-security-audit.json",
        _report(
            "https://github.com/org/repo1",
            [
                _finding("R1B-001", "high", "fp-r1-vuln"),
                _finding("R1B-002", "low", "fp-r1-branch-only"),
            ],
        ),
    )

    # repo2 (owned, HEAD): audit + findings-current (dispositions win)
    _write(
        ar / "findings/prodA/repo2/repo2-security-audit.json",
        _report(
            "https://github.com/org/repo2",
            [
                _finding("R2-001", "critical", "fp-r2-crit"),
                _finding("R2-002", "medium", "fp-r2-fixed"),
                _finding("R2-003", "high", "fp-r2-fp"),
            ],
        ),
    )
    fc = _report(
        "https://github.com/org/repo2",
        [
            dict(
                _finding("R2-001", "critical", "fp-r2-crit"),
                disposition={"validity": "confirmed", "resolution": "open"},
            ),
            dict(
                _finding("R2-002", "medium", "fp-r2-fixed"),
                disposition={"validity": "confirmed", "resolution": "resolved"},
            ),
            dict(
                _finding("R2-003", "high", "fp-r2-fp"),
                disposition={"validity": "false_positive", "resolution": "open"},
            ),
        ],
    )
    _write(ar / "findings/prodA/repo2/repo2-findings-current.json", fc)
    (ar / "findings/prodA/repo2/repo2-triage.json").write_text("{}")

    # repo2 also ships in prodB via a symlink, with its own stale ledger
    linkdir = ar / "findings/prodB/repo2"
    linkdir.mkdir(parents=True)
    (linkdir / "repo2-security-audit.json").symlink_to(
        ar / "findings/prodA/repo2/repo2-security-audit.json"
    )
    (linkdir / "repo2-findings-current.json").write_text("{}")

    # same severity fingerprint seen at two severities -> max wins
    _write(
        ar / "findings/prodA/repo3/repo3-security-audit.json",
        _report(
            "https://github.com/org/repo3",
            [
                _finding("R3-001", "low", "fp-shared-sev"),
                _finding("R3-002", "critical", "fp-shared-sev"),
            ],
        ),
    )

    # md-only report (no JSON sibling)
    p = ar / "findings/prodA/mdonly/mdonly-security-audit.md"
    p.parent.mkdir(parents=True)
    p.write_text("# audit\n", encoding="utf-8")

    # upstream tree
    _write(
        ar / "oss-findings/orgx/uprepo/uprepo-security-audit.json",
        _report(
            "https://github.com/orgx/uprepo",
            [
                _finding("U1-001", "medium", "fp-up-1"),
            ],
        ),
    )

    return ar, bc.corpus.load_config(cfg_path)


def test_ownership_cuts(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    owned = cen["ownership_cuts"]["owned"]
    # distinct: fp-r1-vuln, fp-r2-crit, fp-r2-fixed, fp-shared-sev
    assert owned["distinct_vulnerabilities"] == 4
    # fp-r2-fixed resolved -> open: r1-vuln, r2-crit, shared-sev
    assert owned["distinct_open"] == 3
    assert owned["distinct_by_severity"]["critical"] == 2  # r2-crit + max(shared)
    assert owned["distinct_by_severity"]["high"] == 1
    assert owned["distinct_by_severity"]["low"] == 0  # max-severity wins
    assert owned["hardening_distinct"] == 1
    assert owned["fp_dropped"] == 2  # audit FP + ledger FP
    assert owned["md_only"] == 1
    up = cen["ownership_cuts"]["upstream"]
    assert up["distinct_vulnerabilities"] == 1
    assert "external-bu" not in cen["ownership_cuts"]  # no such tree here


def test_branch_confirmations(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    v2 = cen["duplication"]["v2_branch_reaudits"]
    assert v2["reports"] == 1
    assert v2["findings"] == 2
    assert v2["head_confirmations"] == 1  # fp-r1-vuln matches HEAD
    assert v2["branch_only_distinct"] == 1  # fp-r1-branch-only
    # branch findings never enter the distinct headline
    assert "fp-r1-branch-only" not in json.dumps(cen["ownership_cuts"]["owned"])


def test_duplication_vectors(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    v1 = cen["duplication"]["v1_symlink_aliases"]
    assert v1["file_aliases"] == 1
    assert v1["canonical_targets"] == 1
    assert v1["ledgers_attached_to_aliases"] == 1
    v3 = cen["duplication"]["v3_layered_artifacts"]
    assert v3["with_triage"] == 1
    # repo1 head, repo1 branch, repo2, repo3, mdonly, uprepo = 6 reports
    assert v3["reports"] == 6
    assert cen["duplication"]["v5_duplicate_basenames"]["basenames"] == 0
    assert cen["parse_error_count"] == 0


def test_renderers_and_registered_engagements(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    md = bc.render_md(cen, cfg)
    assert "Distinct vulnerabilities: 4 (3 open)" in md
    assert "registered, no output" in md  # contoso reserved row
    assert "## Duplication vectors" in md
    assert "## Population" in md  # standard block embedded
    html = bc.render_html(cen)
    assert "Corpus Census" in html and "census" not in cen["warnings"]
    # JSON round-trip after stripping the resolution handle
    cen.pop("_resolution")
    json.dumps(cen)


def test_per_ref_breakdown_in_outputs(workspace):
    """Branch-awareness Phase 1: the census surfaces the
    additive per-ref counter as a compact table in md and html."""
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    assert cen["population"]["totals"]["refs"] == {"release-4.19": 1}
    assert cen["population"]["trees"]["findings"]["refs"] == {"release-4.19": 1}
    md = bc.render_md(cen, cfg)
    assert "### Per-ref breakdown" in md
    assert "| `release-4.19` | 1 |" in md
    html = bc.render_html(cen)
    assert "Per-ref breakdown" in html
    assert "<code>release-4.19</code>" in html


def test_classify():
    assert bc.classify({"validation_status": "hardening"}, False) == ("hardening", "open")
    assert bc.classify(
        {"disposition": {"validity": "false_positive", "resolution": "open"}}, True
    ) == ("false_positive", "open")
    assert bc.classify({}, False) == ("not_verified", "open")


@pytest.mark.skipif(
    not (LIVE_ROOT / "findings").is_dir() or os.environ.get("HARNESS_TEST_FIXTURE_CONFIG"),
    reason="needs the sibling analysis-results/ checkout and its "
    "operational corpus config, not the fixture template",
)
def test_live_smoke():
    engine = load_engine()
    cen = bc.run_census(LIVE_ROOT, engine.corpus.config())
    owned = cen["ownership_cuts"]["owned"]
    assert owned["distinct_vulnerabilities"] > 5000
    assert owned["distinct_open"] <= owned["distinct_vulnerabilities"]
    assert cen["duplication"]["v2_branch_reaudits"]["reports"] > 1000
    assert cen["parse_error_count"] == 0
