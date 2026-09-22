"""Tests for harnessing/census/scripts/build_census.py — the corpus census.

The census reads storage/v1 views out of findings.db, so the fixture builds
that store from CONTRACT-VALID artifacts (a report the schema rejects is in
none of the views, which the census then reports as a rejection).
"""

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from traust_engine.corpus import findings_db

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


def _fp(name: str) -> str:
    """A contract-shaped fingerprint (64 hex) that is stable per name."""
    return hashlib.sha256(name.encode()).hexdigest()


def _report(repo_url, findings, *, disposition_aware=False):
    """A report.schema.json-valid document: the minimum the contract accepts."""
    document = {
        "title": "Security audit",
        "metadata": {"date": "2026-06-01", "scope": "repository", "repository": repo_url},
        "executive_summary": {
            "prose": "p" * 50,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {"level": level, "definition": "d" * 20}
            for level in ("critical", "high", "medium", "low")
        ],
        "findings": findings,
        "findings_summary": [
            {"severity": level, "count": 0, "finding_ids": []}
            for level in ("critical", "high", "medium", "low")
        ],
        "remediation_roadmap": [{"priority": "1", "action": "a" * 10, "addresses": ["x"]}],
    }
    if disposition_aware:
        # report_current prefers the disposition-aware restatement.
        document["disposition_summary"] = {
            "layer_ref": "findings-layer.json",
            "generated_at": "2026-07-01T00:00:00Z",
            "by_resolution": {
                "open": 0,
                "fix_in_progress": 0,
                "resolved": 0,
                "partially_resolved": 0,
                "risk_accepted": 0,
                "regression_introduced": 0,
            },
            "by_validity": {"confirmed": 0, "corrected": 0, "false_positive": 0, "not_verified": 0},
        }
    return document


def _finding(fid, sev, fp, validation_status=None, disposition=None):
    f = {
        "id": fid,
        "title": f"Finding {fid}",
        "severity": sev,
        "fingerprint": _fp(fp),
        "cwes": ["CWE-287"],
        "locations": [{"path": "pkg/a.go"}],
        "description": "x" * 50,
        "remediation": "r" * 20,
    }
    if validation_status:
        f["validation_status"] = validation_status
    if disposition:
        f["disposition"] = {
            **disposition,
            "last_updated": "2026-07-01T00:00:00Z",
            "events": [],
        }
    return f


def _write(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture
def workspace(tmp_path):
    cfg_path = tmp_path / "corpus-config.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    ar = tmp_path / "analysis-results"

    # repo1 (owned, HEAD): plain audit — 1 vuln, plus one finding the AUDIT
    # itself calls hardening and one it calls a false positive
    # (validation_status, no ledger). See test_undispositioned_self_classification.
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
            _finding(
                "R2-001",
                "critical",
                "fp-r2-crit",
                disposition={"validity": "confirmed", "resolution": "open"},
            ),
            _finding(
                "R2-002",
                "medium",
                "fp-r2-fixed",
                disposition={"validity": "confirmed", "resolution": "resolved"},
            ),
            _finding(
                "R2-003",
                "high",
                "fp-r2-fp",
                disposition={"validity": "false_positive", "resolution": "open"},
            ),
        ],
        disposition_aware=True,
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

    # same fingerprint seen at two severities -> highest by rank wins
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

    cfg = bc.corpus.load_config(cfg_path)
    # The census reads the storage/v1 views; build the store the way the
    # projection stage does.
    findings_db.build(ar, ar / "graph" / "findings.db", cfg=cfg)
    return ar, cfg


def test_ownership_cuts(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    owned = cen["ownership_cuts"]["owned"]
    # distinct at HEAD: fp-r1-vuln, fp-r1-hard, fp-r1-fp (see the
    # self-classification test), fp-r2-crit, fp-r2-fixed, fp-shared-sev
    assert owned["distinct_vulnerabilities"] == 6
    # fp-r2-fixed resolved -> not open
    assert owned["distinct_open"] == 5
    assert owned["distinct_by_severity"]["critical"] == 2  # r2-crit + max(shared)
    assert owned["distinct_by_severity"]["high"] == 2  # r1-vuln, r1-fp
    assert owned["distinct_by_severity"]["low"] == 0  # highest severity by rank wins
    assert owned["fp_dropped"] == 1  # the ledger's false positive (R2-003)
    assert owned["md_only"] == 1
    assert owned["head_reports"] == 4  # repo1, repo2, repo3, mdonly
    up = cen["ownership_cuts"]["upstream"]
    assert up["distinct_vulnerabilities"] == 1
    assert "external-bu" not in cen["ownership_cuts"]  # no such tree here


def test_undispositioned_self_classification(workspace):
    """A plain audit's own `validation_status` does not reach the spine.

    R1-002 calls itself hardening and R1-003 a false positive, with no ledger
    behind either. The contract's `current_finding` classifies on
    `disposition.validity` alone, so both count as open vulnerabilities here.
    The legacy census honoured `validation_status` when no disposition
    existed (hardening 1, fp_dropped 2 on this fixture); the report schema
    defines those values, so whether the spine should fall back to them is
    decision D8 in the dashboard plan. This test pins the CURRENT contract
    behaviour so the choice is made deliberately, not by drift.
    """
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    owned = cen["ownership_cuts"]["owned"]
    assert owned["hardening_distinct"] == 0
    assert owned["fp_dropped"] == 1


def test_branch_confirmations(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    v2 = cen["duplication"]["v2_branch_reaudits"]
    assert v2["reports"] == 1
    assert v2["findings"] == 2
    assert v2["head_confirmations"] == 1  # fp-r1-vuln matches HEAD
    assert v2["branch_only_distinct"] == 1  # fp-r1-branch-only
    # branch findings never enter the distinct headline
    assert cen["ownership_cuts"]["owned"]["distinct_vulnerabilities"] == 6


def test_duplication_vectors(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    # Symlink aliases are a WALK-time fact. With findings.db present the
    # resolution is rehydrated from `repos`, which carries records and not
    # aliases, so the index path reports zero -- exactly what the production
    # census has reported since it preferred the index (2026-08-20). Pinned
    # here so the gap is visible; a walk (prefer_index=False) still finds
    # the prodB/repo2 alias.
    v1 = cen["duplication"]["v1_symlink_aliases"]
    assert v1["file_aliases"] == 0
    walked = bc.report_store.load_resolution(ar, cfg, prefer_index=False)
    assert sum(1 for a in walked.aliases if a["kind"] == "file") == 1
    v3 = cen["duplication"]["v3_layered_artifacts"]
    assert v3["with_triage"] == 1
    # repo1 head, repo1 branch, repo2, repo3, mdonly, uprepo = 6 reports
    assert v3["reports"] == 6
    assert cen["duplication"]["v5_duplicate_basenames"]["basenames"] == 0


def test_rejections_are_reported_not_hidden(workspace):
    """An artifact the contract refuses is in none of the views; the census
    says how many, and why, rather than counting around it. repo2's `{}`
    triage is the one rejection this fixture carries."""
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    assert cen["parse_error_count"] == cen["storage"]["artifacts_rejected"] == 1
    assert cen["storage"]["artifacts_accepted"] >= 5
    assert any("required" in reason for reason in cen["storage"]["rejection_reasons"])
    assert cen["storage"]["storage_revision"] and cen["storage"]["built_at"]


def test_renderers_and_registered_engagements(workspace):
    ar, cfg = workspace
    cen = bc.run_census(ar, cfg)
    md = bc.render_md(cen, cfg)
    assert "Distinct vulnerabilities: 6 (5 open)" in md
    assert "storage/v1 census views" in md
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


def test_a_stale_store_is_refused(workspace, tmp_path):
    """A findings.db from another revision is refused, never read."""
    ar, cfg = workspace
    import sqlite3

    stale = tmp_path / "stale.db"
    con = sqlite3.connect(stale)
    con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO meta VALUES ('schema_revision', '3')")
    con.commit()
    con.close()
    with pytest.raises(findings_db.StaleFindingsDb):
        bc.run_census(ar, cfg, db_path=stale)


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
    # Rejections are reported from the store, never zeroed by the census.
    assert cen["parse_error_count"] == cen["storage"]["artifacts_rejected"]
