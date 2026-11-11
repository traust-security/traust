"""Input-artifact helpers for backport-fix: remediation synthesis from a
finding (make_remediation.py) and impact-artifact metadata (emitter)."""
import importlib.util
import json
import pathlib
import re

import pytest

_SKILL = pathlib.Path(__file__).resolve().parent.parent / "harnessing" / "7-remediate" / "backport-fix" / "scripts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), _SKILL / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mk = _load("make_remediation.py")
pytest.importorskip("yaml")
emit = _load("emit_backport_report.py")


@pytest.mark.parametrize("raw,want", [
    ("https://github.com/cri-o/cri-o.git", "https://github.com/cri-o/cri-o"),
    ("https://github.com/cri-o/cri-o", "https://github.com/cri-o/cri-o"),
    ("git@github.com:cri-o/cri-o.git", "https://github.com/cri-o/cri-o"),
    ("git@gitlab.cee.redhat.com:grp/proj.git", "https://gitlab.cee.redhat.com/grp/proj"),
])
def test_normalize_repo_url(raw, want):
    assert mk.normalize_repo_url(raw) == want


def test_find_entry_hit_and_miss():
    report = {"findings": [{"id": "f001", "title": "a"}, {"id": "f002"}]}
    assert mk.find_entry(report, "f001")["title"] == "a"
    with pytest.raises(SystemExit):
        mk.find_entry(report, "f404")


def test_resolve_audit_from_source_field(tmp_path):
    audit = {"findings": [{"id": "FIND-001", "cwes": ["CWE-22"]}]}
    (tmp_path / "x-security-audit.json").write_text(json.dumps(audit))
    triage_path = tmp_path / "x-triage.json"
    triage_path.write_text("{}")
    got, audit_id = mk.resolve_audit(
        triage_path, {"source": "x-security-audit.json#FIND-001"}, None
    )
    assert audit_id == "FIND-001"
    assert got == audit


def test_resolve_audit_missing_is_not_fatal(tmp_path):
    triage_path = tmp_path / "x-triage.json"
    triage_path.write_text("{}")
    got, audit_id = mk.resolve_audit(triage_path, {"source": "absent.json#FIND-001"}, None)
    assert got is None and audit_id == "FIND-001"


def test_harness_version_matches_schema_pattern():
    # remediation.schema.json: ^\d+\.\d+\.\d+(-[0-9a-f]{7,40})?$
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9a-f]{7,40})?", mk.harness_version())


def test_change_type_map_covers_git_status_letters():
    assert mk._CHANGE_TYPE["A"] == "added"
    assert mk._CHANGE_TYPE["M"] == "modified"
    assert mk._CHANGE_TYPE["D"] == "deleted"
    assert mk._CHANGE_TYPE["R"] == "renamed"


@pytest.mark.parametrize("raw,want", [
    ("repo:github.com/example/myrepo", "github.com/example/myrepo"),
    ("https://github.com/example/myrepo.git", "github.com/example/myrepo"),
    ("git@github.com:example/myrepo.git", "github.com/example/myrepo"),
    ("github.com/example/myrepo/", "github.com/example/myrepo"),
])
def test_emitter_normalizes_repo_ids(raw, want):
    assert emit._norm_repo_id(raw) == want


def test_impact_metadata_single_repo(tmp_path):
    art = tmp_path / "cve-2026-4242-impact-analysis.json"
    art.write_text(json.dumps({
        "metadata": {"cve": "CVE-2026-4242", "module": "google.golang.org/grpc",
                     "fixed_version": "1.71.3"},
        "repos": [{"repo": "repo:github.com/example/myrepo",
                   "products": ["example-product"]}],
    }))
    meta = emit.read_impact_metadata(art, None)
    assert meta["finding_refs"] == ["CVE-2026-4242"]
    assert meta["repository"] == "https://github.com/example/myrepo"
    assert meta["logical_product"] == "example-product"
    # the advisory carries neither; both resolve from the run's configs
    assert meta["fix_commit"] == "" and meta["base_ref"] == ""


def test_impact_metadata_preserves_repo_case(tmp_path):
    art = tmp_path / "case-impact-analysis.json"
    art.write_text(json.dumps({
        "metadata": {"cve": "CVE-2026-1"},
        "repos": [{"repo": "repo:gitlab.cee.redhat.com/Org/Proj"}],
    }))
    meta = emit.read_impact_metadata(art, "gitlab.cee.redhat.com/org/proj")
    # matching is case-insensitive; the emitted URL keeps the entry's casing
    assert meta["repository"] == "https://gitlab.cee.redhat.com/Org/Proj"


def test_resolve_from_configs_rejects_mixed_runs(tmp_path):
    for branch, sha in (("release-1", "a" * 40), ("release-2", "b" * 40)):
        d = tmp_path / branch
        d.mkdir()
        (d / "config.yaml").write_text(
            f"fix:\n  commit: {sha}\nbranches:\n  source: origin/main\n"
        )
    with pytest.raises(SystemExit):
        emit.resolve_from_configs(tmp_path)


def test_resolve_from_configs_agreeing_runs(tmp_path):
    for branch in ("release-1", "release-2"):
        d = tmp_path / branch
        d.mkdir()
        (d / "config.yaml").write_text(
            "fix:\n  commit: " + "c" * 40 + "\nbranches:\n  source: origin/main\n"
        )
    out = emit.resolve_from_configs(tmp_path)
    assert out == {"fix_commit": "c" * 40, "source_branch": "main"}


def test_impact_metadata_requires_repo_selector_when_ambiguous(tmp_path):
    art = tmp_path / "multi-impact-analysis.json"
    art.write_text(json.dumps({
        "metadata": {"cve": "CVE-2026-4242"},
        "repos": [{"repo": "repo:github.com/a/one"}, {"repo": "repo:github.com/b/two"}],
    }))
    with pytest.raises(SystemExit):
        emit.read_impact_metadata(art, None)
    meta = emit.read_impact_metadata(art, "github.com/b/two")
    assert meta["repository"] == "https://github.com/b/two"


def _branch_repo(tmp_path, branch="amalgamator/backport-cri-o-f001-release-a"):
    """A source clone with the preserved branch, as the Amalgamator leaves it."""
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    def g(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True,
                       capture_output=True, text=True)
    g("init", "-q", "-b", "main")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
      "--allow-empty", "-m", "fix")
    g("branch", branch)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", branch],
                          check=True, capture_output=True, text=True).stdout.strip()
    return repo, head


def _result_dir(tmp_path, repo, *, tracker=None, outcome="success"):
    d = tmp_path / "results" / "release-a"
    d.mkdir(parents=True)
    (d / "config.yaml").write_text(
        "repository:\n  source_path: " + str(repo)
        + "\nfix:\n  commit: " + "c" * 40
        + "\nbranches:\n  source: origin/main\n"
    )
    (d / "summary.json").write_text(json.dumps(
        {"targets": [{"outcome": outcome,
                      "issue_id": "backport-cri-o-f001-release-a"}]}
    ))
    if tracker is not None:
        (d / "tracker.json").write_text(json.dumps(tracker))
    return d


def test_backport_commit_derived_from_preserved_branch(tmp_path):
    # The current Amalgamator tracker has no backport_commit key; a successful
    # run preserves amalgamator/<issue_id>, so the head is the provenance.
    repo, head = _branch_repo(tmp_path)
    d = _result_dir(tmp_path, repo)
    row = emit.read_branch_result(d, emit._source_repo(d))
    assert row["backport_commit"] == head
    assert row["backport_branch"] == "amalgamator/backport-cri-o-f001-release-a"


def test_tracker_value_still_wins_over_branch_head(tmp_path):
    repo, head = _branch_repo(tmp_path)
    other = "d" * 40
    d = _result_dir(tmp_path, repo, tracker={"backport_commit": other})
    row = emit.read_branch_result(d, emit._source_repo(d))
    assert row["backport_commit"] == other != head


def test_failed_outcome_never_gets_a_commit(tmp_path):
    # A leftover branch must not stamp provenance onto a failed row.
    repo, _ = _branch_repo(tmp_path)
    d = _result_dir(tmp_path, repo, outcome="failure")
    row = emit.read_branch_result(d, emit._source_repo(d))
    assert "backport_commit" not in row


# ---------------------------------------------------------------------------
# Emitter contract fixes: real branch names, no inferred build/test verdicts,
# mixed-run refusal with an artifact, run-only reporting, published paths.
# ---------------------------------------------------------------------------

def _write_branch(d, *, target="origin/release-4.16", outcome="success",
                  commit="c" * 40, summary_extra=None, result=None):
    d.mkdir(parents=True, exist_ok=True)
    (d / "candidate.patch").write_text(
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    (d / "config.yaml").write_text(
        "repository:\n  source_path: /nonexistent\n"
        f"fix:\n  commit: {commit}\n"
        f"branches:\n  source: origin/main\n  target: {target}\n")
    target_row = {"outcome": outcome, "issue_id": "backport-x",
                  "target_branch": target}
    if summary_extra:
        target_row.update(summary_extra)
    (d / "summary.json").write_text(json.dumps({"targets": [target_row]}))
    if result is not None:
        (d / "result.json").write_text(json.dumps(result))
    else:
        # Collection-time provenance is the normal case; without it the
        # emitter refuses a successful row.
        (d / "result.json").write_text(json.dumps({
            "issue_id": "backport-x",
            "target_branch": target.removeprefix("origin/"),
            "outcome": outcome,
            "head_sha": commit,
        }))


def test_branch_keeps_the_real_target_name(tmp_path):
    d = tmp_path / "release-4-16"      # sanitized directory slug
    _write_branch(d)
    row = emit.read_branch_result(d)
    assert row["branch"] == "release-4.16"   # not the slug


def test_build_and_test_are_omitted_when_not_evidenced(tmp_path):
    d = tmp_path / "release-a"
    _write_branch(d)
    row = emit.read_branch_result(d)
    # A successful pipeline does not prove the build/tests ran.
    assert "build_passed" not in row and "test_passed" not in row


def test_build_and_test_are_kept_when_the_summary_reports_them(tmp_path):
    d = tmp_path / "release-a"
    _write_branch(d, summary_extra={"build_passed": True, "test_passed": False})
    row = emit.read_branch_result(d)
    assert row["build_passed"] is True and row["test_passed"] is False


def test_recorded_head_wins_over_the_moved_branch(tmp_path):
    d = tmp_path / "release-a"
    recorded = "a" * 40
    _write_branch(d, result={"issue_id": "backport-x", "head_sha": recorded,
                             "target_branch": "release-a", "outcome": "success"})
    row = emit.read_branch_result(d)
    assert row["backport_commit"] == recorded


def test_mixed_runs_are_refused_even_with_an_artifact(tmp_path):
    # The artifact supplies a commit; that must not bypass the config
    # agreement check (the bug let two runs be attributed to one fix).
    results = tmp_path / "results"
    _write_branch(results / "release-a", commit="a" * 40)
    _write_branch(results / "release-b", target="origin/release-4.17",
                  commit="b" * 40)
    rem = {
        "seam": "remediation", "audit_report_path": "", "repository": "https://github.com/o/r",
        "logical_product": "p", "language": "", "fix_commit": "a" * 40,
        "fix_branch_name": "", "base_ref": "main", "fork_url": "",
        "cwes": [], "finding_refs": [], "remediation_path": "",
    }
    with pytest.raises(SystemExit):
        emit.build_report(results, rem)


def test_artifact_commit_does_not_override_the_run_commit(tmp_path):
    results = tmp_path / "results"
    run_commit = "c" * 40
    _write_branch(results / "release-a", commit=run_commit)
    rem = {
        "seam": "remediation", "audit_report_path": "", "repository": "https://github.com/o/r",
        "logical_product": "p", "language": "", "fix_commit": "d" * 40,
        "fix_branch_name": "", "base_ref": "main", "fork_url": "",
        "cwes": [], "finding_refs": [], "remediation_path": "",
    }
    report = emit.build_report(results, rem)
    assert report["source_fix"]["commit"] == run_commit


def test_run_only_metadata_comes_from_the_configs(tmp_path):
    results = tmp_path / "results"
    _write_branch(results / "release-a", commit="e" * 40)
    meta = emit.read_run_metadata(results, "https://github.com/o/r", "prod")
    assert meta["fix_commit"] == "e" * 40
    assert meta["base_ref"] == "main"
    assert meta["repository"] == "https://github.com/o/r"


def test_publish_rewrites_patch_paths_to_the_published_files(tmp_path, monkeypatch):
    monkeypatch.setattr(emit, "workspace_root", lambda: tmp_path)
    results = tmp_path / "results"
    d = results / "release-a"
    _write_branch(d)
    report = {"target_branches": [
        {"branch": "release-a", "status": "success",
         "patch_path": str(d / "candidate.patch")},
    ]}
    rem = {"repository": "https://github.com/o/r", "logical_product": "p"}
    dest = emit.publish_results(tmp_path / "pub", results, report, rem)
    assert dest is not None
    published = json.loads((dest / "r-backport-report.json").read_text())
    path = published["target_branches"][0]["patch_path"]
    assert not path.startswith("/") and path.endswith(".patch")
    assert (tmp_path / path).is_file()


def test_tracker_cannot_override_the_recorded_head(tmp_path):
    d = tmp_path / "release-a"
    recorded = "a" * 40
    _write_branch(d, result={"issue_id": "backport-x", "head_sha": recorded,
                             "target_branch": "release-a", "outcome": "success"})
    (d / "tracker.json").write_text(json.dumps({"backport_commit": "b" * 40}))
    row = emit.read_branch_result(d)
    assert row["backport_commit"] == recorded


def test_empty_recorded_head_does_not_fall_back_to_the_mutable_branch(tmp_path):
    import subprocess
    repo = tmp_path / "repo"; repo.mkdir()
    def g(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True,
                       capture_output=True, text=True)
    g("init", "-q", "-b", "main")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
      "--allow-empty", "-m", "fix")
    g("branch", "amalgamator/backport-x")
    d = tmp_path / "release-a"
    _write_branch(d, result={"issue_id": "backport-x", "head_sha": "",
                             "target_branch": "release-a", "outcome": "success"})
    row = emit.read_branch_result(d, repo)
    # result.json exists, so no tracker/branch substitution may fabricate one.
    assert "backport_commit" not in row


def test_verification_hint_prefers_the_commit_over_the_branch(tmp_path):
    results = tmp_path / "results"
    sha = "c" * 40
    _write_branch(results / "release-a", commit=sha)
    (results / "release-a" / "result.json").write_text(json.dumps(
        {"issue_id": "backport-x", "head_sha": sha,
         "target_branch": "release-a", "outcome": "success"}))
    rem = {
        "seam": "remediation", "audit_report_path": "", "repository": "https://github.com/o/r",
        "logical_product": "p", "language": "", "fix_commit": sha,
        "fix_branch_name": "", "base_ref": "main", "fork_url": "",
        "cwes": [], "finding_refs": [], "remediation_path": "",
    }
    report = emit.build_report(results, rem)
    hint = report["verification_hint"]
    assert "command" not in hint          # inputs only; no command line
    branch = hint["branches"][0]
    assert branch["target_branch"] == "release-a"
    assert branch["backport_commit"] == sha



def test_worklist_skips_succeeded_without_a_patch():
    wl = _load("emit_backport_worklist.py")
    report = {
        "metadata": {"repository": "https://github.com/o/r"},
        "source_fix": {"finding_refs": ["t#f001"], "commit": "a" * 40,
                       "branch": "main"},
        "target_branches": [
            {"branch": "release-1", "status": "succeeded", "has_patch": False},
            {"branch": "release-2", "status": "succeeded", "has_patch": True},
        ],
    }
    worklist = wl.build_worklist(report, "r.json")
    assert [e["target_branch"] for e in worklist["entries"]] == ["release-2"]


def test_worklist_selects_the_emitted_succeeded_status(tmp_path):
    # Regression: the emitter writes the contract's `succeeded`, so a filter
    # keyed on the old `success`/`passed` names left every patched branch out.
    wl = _load("emit_backport_worklist.py")
    results = tmp_path / "results"
    _write_branch(results / "release-a")
    rem = {
        "seam": "remediation", "audit_report_path": "",
        "repository": "https://github.com/o/r", "logical_product": "p",
        "language": "", "fix_commit": "c" * 40, "fix_branch_name": "",
        "base_ref": "main", "fork_url": "", "cwes": [],
        "finding_refs": ["t#f001"], "remediation_path": "",
    }
    report = emit.build_report(results, rem)
    assert report["target_branches"][0]["status"] == "succeeded"

    worklist = wl.build_worklist(report, "r.json")
    # The report carries the real target name, not the directory slug.
    assert [e["target_branch"] for e in worklist["entries"]] == ["release-4.16"]
    entry = worklist["entries"][0]
    assert entry["suggested_disposition"] == "fix_in_progress"
    assert entry["has_patch"] is True
    assert entry["backport_commit"] == "c" * 40
    assert entry["finding_refs"] == ["t#f001"]


def test_worklist_ignores_failed_and_skipped(tmp_path):
    # failed/skipped branches may carry cost and an error but no patch to
    # merge; they must not suggest fix_in_progress.
    wl = _load("emit_backport_worklist.py")
    report = {
        "metadata": {"repository": "https://github.com/o/r"},
        "source_fix": {"finding_refs": ["t#f001"], "commit": "a" * 40,
                       "branch": "main"},
        "target_branches": [
            {"branch": "release-1", "status": "failed",
             "stop_reason": "error", "has_patch": True},
            {"branch": "release-2", "status": "skipped"},
        ],
    }
    assert wl.build_worklist(report, "r.json")["entries"] == []


def test_publish_failure_keeps_the_previous_publication(tmp_path, monkeypatch):
    results = tmp_path / "results"
    for b in ("release-a", "release-b"):
        _write_branch(results / b, target=f"origin/{b}")
    rem = {"repository": "https://github.com/o/r", "logical_product": "p"}
    dest = emit.publish_results(tmp_path / "pub", results,
                                {"target_branches": []}, rem)
    assert dest is not None
    before = {p.name: p.read_text() for p in dest.iterdir()}

    real = emit._copy_untrusted_file
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        return False if calls["n"] == 2 else real(src, dst)

    monkeypatch.setattr(emit, "_copy_untrusted_file", flaky)
    report = {"target_branches": [
        {"branch": "release-a", "status": "success",
         "patch_path": str(results / "release-a" / "candidate.patch")},
        {"branch": "release-b", "status": "success",
         "patch_path": str(results / "release-b" / "candidate.patch")},
    ]}
    assert emit.publish_results(tmp_path / "pub", results, report, rem) is None
    after = {p.name: p.read_text() for p in dest.iterdir()}
    assert after == before


def test_success_row_without_provenance_is_refused(tmp_path):
    results = tmp_path / "results"
    _write_branch(results / "release-a")
    (results / "release-a" / "result.json").unlink()   # no collection record
    rem = {
        "seam": "remediation", "audit_report_path": "",
        "repository": "https://github.com/o/r", "logical_product": "p",
        "language": "", "fix_commit": "c" * 40, "fix_branch_name": "",
        "base_ref": "main", "fork_url": "", "cwes": [], "finding_refs": [],
        "remediation_path": "",
    }
    with pytest.raises(SystemExit):
        emit.build_report(results, rem)


def test_engine_failure_overrides_a_success_shaped_summary(tmp_path):
    # summary.json and candidate.patch can look successful while the engine
    # exited nonzero; the recorded verdict must decide the report.
    results = tmp_path / "results"
    _write_branch(results / "release-a")
    (results / "release-a" / "result.json").write_text(json.dumps({
        "issue_id": "backport-x", "target_branch": "release-a",
        "outcome": "failed", "summary_outcome": "success",
        "engine_exit_code": 1, "head_sha": "c" * 40,
    }))
    rem = {
        "seam": "remediation", "audit_report_path": "",
        "repository": "https://github.com/o/r", "logical_product": "p",
        "language": "", "fix_commit": "c" * 40, "fix_branch_name": "",
        "base_ref": "main", "fork_url": "", "cwes": [], "finding_refs": [],
        "remediation_path": "",
    }
    report = emit.build_report(results, rem)
    row = report["target_branches"][0]
    assert row["status"] == "failed"
    assert "engine exited 1" in row["error"]
    assert report["summary"]["failed"] == 1
    assert report["summary"]["succeeded"] == 0


@pytest.mark.parametrize("payload", [
    "[]",                      # top-level array
    "null",                    # top-level null
    '{"targets": [null]}',     # target entry is not an object
    '{"targets": "nope"}',     # targets is not an array
])
def test_malformed_summary_is_a_branch_error(tmp_path, payload):
    results = tmp_path / "results"
    d = results / "release-a"
    _write_branch(d)
    (d / "summary.json").write_text(payload)

    row = emit.read_branch_result(d, emit._source_repo(d))
    assert row["status"] == "error"
    assert "summary.json" in row["error"]

    rem = {
        "seam": "remediation", "audit_report_path": "",
        "repository": "https://github.com/o/r", "logical_product": "p",
        "language": "", "fix_commit": "c" * 40, "fix_branch_name": "",
        "base_ref": "main", "fork_url": "", "cwes": [], "finding_refs": [],
        "remediation_path": "",
    }
    report = emit.build_report(results, rem)
    branch = report["target_branches"][0]
    assert branch["status"] == "failed"
    assert branch["stop_reason"] == "error"
