"""Branch-selection policy of the backport-fix generator: only
deterministic patch-id matches may auto-exclude a branch."""
import importlib.util
import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

_MOD_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "harnessing" / "7-remediate" / "backport-fix" / "scripts" / "generate_backport_configs.py"
)
_spec = importlib.util.spec_from_file_location("backport_gen", _MOD_PATH)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


class _EnumLike:
    def __init__(self, value):
        self.value = value


@pytest.mark.parametrize("status,bucket", [
    ("EXACT_MATCH", "already_fixed"),
    ("EQUIVALENT", "already_fixed"),
    ("EQUIVALENT_PATCH", "already_fixed"),
    ("NOT_AFFECTED", "not_affected"),
    ("NEEDS_FIX", "needs_fix"),
    ("LIKELY_PRESENT", "ambiguous"),
    ("AMBIGUOUS", "ambiguous"),
    ("ERROR", "ambiguous"),
    ("", "ambiguous"),
    # scanner JSON display names (subprocess-fallback wire form):
    # ALREADY_FIXED covers exactly EXACT_MATCH+EQUIVALENT; LIKELY_FIXED
    # is the heuristic and must reach needs-review
    ("ALREADY_FIXED", "already_fixed"),
    ("LIKELY_FIXED", "ambiguous"),
])
def test_bucket_names(status, bucket):
    assert gen._bucket_scan_status(status) == bucket


@pytest.mark.parametrize("wire,bucket", [
    ("exact_match", "already_fixed"),
    ("equivalent_patch", "already_fixed"),
    ("not_affected", "not_affected"),
    ("needs_fix", "needs_fix"),
    ("likely_present", "ambiguous"),
    ("ambiguous", "ambiguous"),
    ("error", "ambiguous"),
])
def test_bucket_wire_values_and_enum_members(wire, bucket):
    assert gen._bucket_scan_status(wire) == bucket
    assert gen._bucket_scan_status(_EnumLike(wire)) == bucket


def test_likely_present_never_auto_excluded():
    # The heuristic verdict must reach needs-review, not silent exclusion.
    assert gen._bucket_scan_status("LIKELY_PRESENT") != "already_fixed"
    assert gen._bucket_scan_status(_EnumLike("likely_present")) != "already_fixed"


# ---------------------------------------------------------------------------
# Subprocess fallback (used when backport_scanner is not importable in this
# interpreter). Pins the three defects found against the current scanner:
# stdout is not JSON, the report key is refs[] (name/raw_status), and the exit
# code is a verdict (0/1/3) rather than a failure signal.
# ---------------------------------------------------------------------------

import json as _json
import subprocess as _subprocess


class _FakeRun:
    def __init__(self, returncode, refs):
        self.returncode = returncode
        self.refs = refs
        self.stderr = ""

    def __call__(self, cmd, **kwargs):
        # Interpreter probe (`-c "import backport_scanner..."`): report success.
        if "--output" not in cmd:
            return _subprocess.CompletedProcess(cmd, 0, "", "")
        # The scanner writes JSON only to --output; stdout is human-readable.
        out = cmd[cmd.index("--output") + 1]
        pathlib.Path(out).write_text(_json.dumps({"refs": self.refs}))
        return _subprocess.CompletedProcess(cmd, self.returncode, "REPORT TEXT\n", "")


def _fallback(monkeypatch, returncode, refs):
    monkeypatch.setattr(gen.subprocess, "run", _FakeRun(returncode, refs))
    return gen.scan_branches_subprocess(pathlib.Path("/tmp/repo"), "a" * 40)


@pytest.mark.parametrize("returncode", [0, 1, 3])
def test_fallback_accepts_verdict_exit_codes(monkeypatch, returncode):
    # 1 = needs_fix and 3 = ambiguous are successful scans, not failures.
    buckets = _fallback(monkeypatch, returncode, [
        {"name": "release-a", "ref_type": "branch", "raw_status": "needs_fix"},
    ])
    assert buckets["needs_fix"] == ["release-a"]


def test_fallback_reads_refs_name_and_raw_status(monkeypatch):
    buckets = _fallback(monkeypatch, 0, [
        {"name": "release-a", "ref_type": "branch", "raw_status": "exact_match"},
        {"name": "release-b", "ref_type": "branch", "raw_status": "likely_present"},
        {"name": "release-c", "ref_type": "branch", "raw_status": "not_affected"},
        {"name": "v1.0", "ref_type": "tag", "raw_status": "needs_fix"},
    ])
    assert buckets["already_fixed"] == ["release-a"]
    # heuristic verdict still reaches needs-review, never auto-exclusion
    assert buckets["ambiguous"] == ["release-b"]
    assert buckets["not_affected"] == ["release-c"]
    # tags are not branch-selection candidates
    assert buckets["total"] == 3


def test_fallback_rejects_exit_2(monkeypatch):
    monkeypatch.setattr(gen.subprocess, "run", _FakeRun(2, []))
    with pytest.raises(SystemExit):
        gen.scan_branches_subprocess(pathlib.Path("/tmp/repo"), "a" * 40)


# ---------------------------------------------------------------------------
# go.mod parsing: version-qualified replace directives and ref errors
# ---------------------------------------------------------------------------

def test_version_qualified_replace_only_applies_to_the_required_version():
    # replace dep v1.0.0 => dep v1.9.0 does NOT apply when v1.2.0 is required;
    # honouring it unconditionally made a vulnerable branch look bumped.
    text = "module x\nrequire dep v1.2.0\nreplace dep v1.0.0 => dep v1.9.0\n"
    assert gen._module_version_from_gomod(text, "dep") == "v1.2.0"


def test_version_qualified_replace_applies_when_it_matches():
    text = "module x\nrequire dep v1.2.0\nreplace dep v1.2.0 => dep v1.9.0\n"
    assert gen._module_version_from_gomod(text, "dep") == "v1.9.0"


def test_unqualified_replace_still_applies():
    text = "module x\nrequire dep v1.2.0\nreplace dep => dep v1.9.0\n"
    assert gen._module_version_from_gomod(text, "dep") == "v1.9.0"


def test_path_replace_is_ambiguous():
    text = "module x\nrequire dep v1.2.0\nreplace dep => ../local\n"
    assert gen._module_version_from_gomod(text, "dep") == "path"


def test_unknown_ref_is_ambiguous_not_absent(tmp_path):
    import subprocess
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    # A missing ref must never read as "module absent" (=> NOT_AFFECTED).
    assert gen.module_version_at(tmp_path, "origin/does-not-exist", "dep") == (
        "ambiguous", None,
    )


def test_exact_replace_beats_wildcard_regardless_of_order():
    # Go: an exact-version replacement wins over a wildcard one, whatever the
    # directive order. Last-match-wins inverted this and hid a vulnerable pin.
    text = ("module x\nrequire dep v1.2.0\n"
            "replace dep => dep v1.9.0\n"
            "replace dep v1.2.0 => dep v1.3.0\n")
    assert gen._module_version_from_gomod(text, "dep") == "v1.3.0"


def test_safe_slug_is_allowlisted_and_collision_safe():
    used = set()
    slug = gen.safe_slug("release-1';__import__('os').system('id');'", used)
    assert re.fullmatch(r"[A-Za-z0-9._-]+", slug), slug
    dotted = gen.safe_slug("release-1.2", used)
    slashed = gen.safe_slug("release-1/2", used)
    assert dotted != slashed, (dotted, slashed)


def test_slug_collision_suffix_is_itself_checked():
    used = set()
    first = gen.safe_slug("release-1.2", used)
    # Pre-seed the obvious hash candidate so the allocator must keep going.
    import hashlib
    digest = hashlib.sha256("release-1/2".encode()).hexdigest()[:8]
    used.add(f"{first}-{digest}")
    second = gen.safe_slug("release-1/2", used)
    assert second not in used - {second}
    assert second != f"{first}-{digest}"
    assert len({first, second}) == 2


def test_slug_never_yields_a_dot_directory():
    assert gen.safe_slug("..") == "branch"
    assert gen.safe_slug("...yaml") == "yaml"


def test_config_uses_the_allocated_slug_for_issue_id_and_workdir(tmp_path):
    cfg = gen.make_config_yaml(
        repo_path=tmp_path, fix_commit="a" * 40,
        target_branch="release-1/2", source_branch="main",
        bug_description="t", safe_branch="release-1-2-deadbeef",
    )
    assert "release-1-2-deadbeef" in cfg["issue_id"]
    assert "release-1-2-deadbeef" in cfg["repository"]["workdir"]


def test_triage_enrichment_follows_the_finding_reference(tmp_path):
    import json
    triage = tmp_path / "triage.json"
    triage.write_text(json.dumps({"findings": [
        {"id": "f001", "title": "unrelated", "severity": "low"},
        {"id": "f002", "title": "wanted", "severity": "high"},
    ]}))
    assert gen.read_triage(triage, ["repo-triage.json#f002"])["title"] == "wanted"
    assert gen.read_triage(triage, ["repo-triage.json#f002"])["severity"] == "high"
    # no match -> first finding, as before
    assert gen.read_triage(triage, ["nope#f999"])["title"] == "unrelated"


@pytest.mark.parametrize("fid", [
    "cve-2026-12345",
    "fix-cve-2026-12345",            # embedded, not anchored
    "ghsa-abcd-efgh-ijkl",           # GHSA advisory
    "GHSA-ABCD-EFGH-IJKL",           # advisories are usually uppercase
    "pre-ghsa-abcd-efgh-ijkl-post",  # embedded GHSA
])
def test_advisory_ids_never_reach_issue_id(fid):
    # Pushed ref names and the preservation branch must not disclose them.
    assert gen.slug_issue_id(
        [f"triage.json#{fid}"], "cri-o", "release-a", "deadbeef"
    ) == "backport-release-a-deadbeef"


def test_plain_finding_id_still_shapes_the_issue_id():
    assert gen.slug_issue_id(
        ["triage.json#f001"], "cri-o", "release-a", "deadbeef"
    ) == "backport-cri-o-f001-release-a"


def _fake_report_run(payload_text, returncode):
    class _Run:
        stderr = ""

        def __call__(self, cmd, **kwargs):
            if "--output" not in cmd:
                return _subprocess.CompletedProcess(cmd, 0, "", "")
            pathlib.Path(cmd[cmd.index("--output") + 1]).write_text(payload_text)
            return _subprocess.CompletedProcess(cmd, returncode, "", "")
    return _Run()


def test_fallback_fails_closed_when_the_scanner_reports_ref_errors(monkeypatch):
    # A crash also exits 1; only the report can distinguish it from the
    # "needs_fix present" verdict.
    monkeypatch.setattr(gen.subprocess, "run", _fake_report_run(
        _json.dumps({"summary": {"errors": 2}, "refs": []}), 1))
    with pytest.raises(SystemExit):
        gen.scan_branches_subprocess(pathlib.Path("/tmp/repo"), "a" * 40)


def test_fallback_fails_closed_on_a_malformed_report(monkeypatch):
    monkeypatch.setattr(gen.subprocess, "run", _fake_report_run("{not json", 1))
    with pytest.raises(SystemExit):
        gen.scan_branches_subprocess(pathlib.Path("/tmp/repo"), "a" * 40)


# ---------------------------------------------------------------------------
# find_bump_commit: an ambiguous parent is not proof of a vulnerable parent
# ---------------------------------------------------------------------------

class _FakeRevGit:
    def __init__(self, shas, has_parent=True):
        self.shas = list(shas)
        self.has_parent = has_parent

    def __call__(self, cmd, **kwargs):
        if "rev-list" in cmd:
            return _subprocess.CompletedProcess(cmd, 0, " ".join(self.shas), "")
        if "rev-parse" in cmd:
            return _subprocess.CompletedProcess(
                cmd, 0 if self.has_parent else 1, "", "")
        raise AssertionError(cmd)


def _bump(monkeypatch, versions, shas=("c1",), has_parent=True):
    def fake_at(repo, ref, module):
        return versions.get(ref, ("absent", None))
    monkeypatch.setattr(gen, "module_version_at", fake_at)
    monkeypatch.setattr(gen.subprocess, "run",
                        _FakeRevGit(shas, has_parent=has_parent))
    return gen.find_bump_commit(
        pathlib.Path("/tmp/repo"), "origin/main", "dep", "v1.71.3")


def _fixed(version):
    return ("found", version)


def test_bump_accepts_a_vulnerable_parent(monkeypatch):
    result = _bump(monkeypatch, {
        "origin/main": _fixed("v1.80.0"),
        "c1": _fixed("v1.80.0"),
        "c1~1": _fixed("v1.50.0"),
    })
    assert result == ("found", "c1")


def test_bump_accepts_a_newly_introduced_module(monkeypatch):
    result = _bump(monkeypatch, {
        "origin/main": _fixed("v1.80.0"),
        "c1": _fixed("v1.80.0"),
        "c1~1": ("absent", None),
    })
    assert result == ("found", "c1")


def test_bump_walks_past_an_already_fixed_parent(monkeypatch):
    result = _bump(monkeypatch, {
        "origin/main": _fixed("v1.80.0"),
        "c1": _fixed("v1.80.0"),
        "c1~1": _fixed("v1.80.0"),
        "c2": _fixed("v1.80.0"),
        "c2~1": _fixed("v1.50.0"),
    }, shas=("c1", "c2"))
    assert result == ("found", "c2")


def test_bump_fails_closed_on_an_ambiguous_parent(monkeypatch):
    # The parent's state cannot prove vulnerability; do not return the child.
    result = _bump(monkeypatch, {
        "origin/main": _fixed("v1.80.0"),
        "c1": _fixed("v1.80.0"),
        "c1~1": ("ambiguous", None),
    })
    assert result == ("not_located", None)


def test_bump_fails_closed_on_an_uncomparable_parent_version(monkeypatch):
    result = _bump(monkeypatch, {
        "origin/main": _fixed("v1.80.0"),
        "c1": _fixed("v1.80.0"),
        "c1~1": _fixed("not-a-version"),
    })
    assert result == ("not_located", None)


def test_bump_accepts_the_root_commit(monkeypatch):
    result = _bump(monkeypatch, {
        "origin/main": _fixed("v1.80.0"),
        "c1": _fixed("v1.80.0"),
        "c1~1": _fixed("v1.50.0"),
    }, has_parent=False)
    assert result == ("found", "c1")
