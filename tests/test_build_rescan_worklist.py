"""Tests for traust.cli.build_rescan_worklist — the continuous-operations
router. No network: gh/glab fetchers are monkeypatched throughout."""

import json
import sqlite3
import textwrap
from pathlib import Path

import pytest

from traust.cli import build_rescan_worklist as rw


@pytest.fixture(autouse=True)
def _register_private_forge(monkeypatch):
    """Register the fixture forge for the duration of each test.

    No private forge ships as a default any more — GIT_HOSTS is deployment
    config — so a test that exercises subgroup parsing has to declare the
    host it is testing, exactly as a real deployment would.
    """
    monkeypatch.setitem(rw.GIT_HOSTS, "gitlab.example.com", "gitlab")


# ---------------------------------------------------------------------------
# decision table
# ---------------------------------------------------------------------------


def _ctx(**over):
    c = {
        "tier": "P1",
        "C": 0,
        "S": False,
        "S_lines": 0,
        "deps_only": False,
        "audit_age_days": 30,
        "changed": False,
        "ahead_by": None,
        "R": None,
    }
    c.update(over)
    return c


class TestDecide:
    def test_rule2_lines(self):
        rule, lane, _ = rw.decide(_ctx(C=8000))
        assert (rule, lane) == ("rule-2", "full-audit")

    def test_rule2_ratio(self):
        rule, lane, _ = rw.decide(_ctx(C=500, R=0.12))
        assert (rule, lane) == ("rule-2", "full-audit")

    def test_rule2_ratio_missing_loc_is_ignored(self):
        # lines_reviewed unrecoverable -> R None -> absolute C governs
        rule, _, _ = rw.decide(_ctx(C=7999, R=None))
        assert rule != "rule-2"

    def test_rule3_sensitive_full_for_p0_p1(self):
        for tier in ("P0", "P1"):
            rule, lane, _ = rw.decide(_ctx(tier=tier, C=500, S=True, S_lines=200))
            assert (rule, lane) == ("rule-3", "full-audit")

    def test_rule3_sensitive_diff_for_p2(self):
        rule, lane, _ = rw.decide(_ctx(tier="P2", C=500, S=True, S_lines=250))
        assert (rule, lane) == ("rule-3", "diff-scan")

    def test_rule3_below_line_floor_falls_through(self):
        rule, _, _ = rw.decide(_ctx(C=500, S=True, S_lines=199))
        assert rule == "rule-5"

    def test_rule3b_deps_only(self):
        rule, lane, _ = rw.decide(_ctx(C=50, deps_only=True))
        assert (rule, lane) == ("rule-3b", "deps-lane")

    def test_rule2_precedes_rule3(self):
        rule, _, _ = rw.decide(_ctx(C=9000, S=True, S_lines=300))
        assert rule == "rule-2"

    def test_rule3_precedes_rule3b(self):
        rule, _, _ = rw.decide(_ctx(C=300, S=True, S_lines=300, deps_only=True))
        assert rule == "rule-3"

    def test_rule4_ceilings(self):
        for tier, ceiling in (("P0", 180), ("P1", 270), ("P2", 365)):
            rule, lane, _ = rw.decide(_ctx(tier=tier, audit_age_days=ceiling + 1))
            assert (rule, lane) == ("rule-4", "full-audit"), tier
            rule, _, _ = rw.decide(_ctx(tier=tier, audit_age_days=ceiling))
            assert rule != "rule-4", tier

    def test_rule4_no_ceiling_for_p3(self):
        rule, lane, _ = rw.decide(_ctx(tier="P3", audit_age_days=9999))
        assert (rule, lane) == ("rule-7", "none")

    def test_rule5_below_threshold_change(self):
        rule, lane, _ = rw.decide(_ctx(C=100))
        assert (rule, lane) == ("rule-5", "diff-scan-quarterly")

    def test_rule6_tag_noise(self):
        rule, lane, _ = rw.decide(_ctx(changed=True, ahead_by=0))
        assert (rule, lane) == ("rule-6", "none")

    def test_rule7_default_none(self):
        rule, lane, _ = rw.decide(_ctx())
        assert (rule, lane) == ("rule-7", "none")


class TestRiskTier:
    def test_tiers(self):
        assert rw.risk_tier(5, False, False) == "P0"
        assert rw.risk_tier(1, False, False) == "P1"
        assert rw.risk_tier(0, False, False) == "P2"
        assert rw.risk_tier(0, True, False) == "P3"
        assert rw.risk_tier(0, False, True) == "P3"

    def test_live_risk_outranks_dormancy(self):
        assert rw.risk_tier(6, True, True) == "P0"
        assert rw.risk_tier(1, True, False) == "P1"


# ---------------------------------------------------------------------------
# change metrics: first-party filter, sensitive matcher, DEPS_only
# ---------------------------------------------------------------------------


class TestFirstParty:
    @pytest.mark.parametrize(
        "path",
        [
            "vendor/lib/x.go",
            "ui/node_modules/a/b.js",
            "third_party/z/c.cc",
            "dist/bundle.js",
            "pkg/api_generated_types.go",
            "api/v1/types.pb.go",
            "docs/README.md",
            "README.md",
        ],
    )
    def test_excluded(self, path):
        assert not rw.is_first_party(path)

    @pytest.mark.parametrize(
        "path",
        [
            "pkg/auth/handler.go",
            "cmd/main.go",
            "src/session.py",
            "myvendor/x.go",  # component must match exactly, not substring
        ],
    )
    def test_included(self, path):
        assert rw.is_first_party(path)


class TestSensitiveMatcher:
    @pytest.mark.parametrize(
        "path",
        [
            "pkg/auth/login.go",
            "internal/token_store.go",
            "config/TLS_setup.yaml",
            "x/rbac/roles.go",
            "handlers/deserialize.py",
            "a/unmarshal_test.go",
            "jwt/verify.go",
            "oauth2/flow.go",
            "saml/sp.go",
            "net/acl.go",
            "pkg/secrets.go",
            "cert-manager/certs.go",
        ],
    )
    def test_positive(self, path):
        assert rw.SENSITIVE_RX.search(path)

    @pytest.mark.parametrize(
        "path",
        [
            "pkg/controller/reconcile.go",
            "ui/components/table.tsx",
            "Makefile",
            "cmd/server/main.go",
        ],
    )
    def test_negative(self, path):
        assert not rw.SENSITIVE_RX.search(path)


class TestChangeMetrics:
    def test_counts_first_party_only(self):
        files = [
            {"filename": "vendor/x.go", "changes": 5000},
            {"filename": "pkg/main.go", "changes": 100},
            {"filename": "docs/a.md", "changes": 400},
        ]
        m = rw.change_metrics(files)
        assert m["C"] == 100
        assert m["fp_files"] == 1
        assert not m["S"]
        assert not m["deps_only"]

    def test_sensitive_lines(self):
        files = [
            {"filename": "pkg/auth/x.go", "changes": 150},
            {"filename": "pkg/token.go", "changes": 60},
            {"filename": "pkg/other.go", "changes": 10},
        ]
        m = rw.change_metrics(files)
        assert m["S"] and m["S_lines"] == 210 and m["C"] == 220

    def test_deps_only_true(self):
        files = [
            {"filename": "go.mod", "changes": 4},
            {"filename": "go.sum", "changes": 40},
            {"filename": "sub/requirements-dev.txt", "changes": 2},
        ]
        assert rw.change_metrics(files)["deps_only"]

    def test_deps_only_false_when_code_touched(self):
        files = [
            {"filename": "go.mod", "changes": 4},
            {"filename": "pkg/main.go", "changes": 1},
        ]
        assert not rw.change_metrics(files)["deps_only"]

    def test_deps_only_false_when_no_files(self):
        assert not rw.change_metrics([])["deps_only"]


# ---------------------------------------------------------------------------
# URL parsing / injection guards
# ---------------------------------------------------------------------------


class TestSplitRepoUrl:
    def test_github(self):
        assert rw.split_repo_url("https://github.com/org/repo") == (
            "github",
            "github.com",
            "org/repo",
        )

    def test_github_extra_path_trimmed(self):
        kind, _, proj = rw.split_repo_url("https://github.com/org/repo/tree/main")
        assert (kind, proj) == ("github", "org/repo")

    def test_gitlab_subgroup(self):
        kind, host, proj = rw.split_repo_url("https://gitlab.example.com/service/app/sub/repo")
        assert kind == "gitlab"
        assert host == "gitlab.example.com"
        assert proj == "service/app/sub/repo"

    def test_gitlab_com(self):
        assert rw.split_repo_url("https://gitlab.com/g/r")[0] == "gitlab"

    def test_unsupported_host(self):
        kind, host, _ = rw.split_repo_url("https://example.com/a/b")
        assert kind is None and host == "example.com"

    def test_no_url(self):
        assert rw.split_repo_url(None) == (None, None, None)


class TestInjectionGuards:
    def test_gh_rejects_unsafe_org(self):
        res = rw.gh_repo_info("../repos/x")
        assert not res["ok"] and "unsafe" in res["error"]

    def test_gh_compare_rejects_unsafe_sha(self):
        res = rw.gh_compare("org/repo", "HEAD;rm -rf")
        assert not res["ok"] and "unsafe" in res["error"]

    def test_gitlab_rejects_traversal_segment(self):
        assert not rw.safe_project_path("group/../other")
        assert not rw.safe_project_path("group//repo")
        assert not rw.safe_project_path("")
        res = rw.gitlab_repo_info("gitlab.example.com", "a/../b")
        assert not res["ok"] and "unsafe" in res["error"]

    def test_safe_paths_pass(self):
        assert rw.safe_project_path("org/repo")
        assert rw.safe_project_path("group/sub-group/my.repo_1")

    def test_gitlab_path_encoding(self):
        assert rw.gitlab_project_enc("group/subgroup/repo") == "group%2Fsubgroup%2Frepo"
        assert rw.gitlab_project_enc("g/r.name") == "g%2Fr.name"


# ---------------------------------------------------------------------------
# GitLab diff-hunk line counter + compare normalization
# ---------------------------------------------------------------------------

DIFF = (
    "--- a/pkg/auth.go\n"
    "+++ b/pkg/auth.go\n"
    "@@ -1,4 +1,5 @@\n"
    " context\n"
    "-old line\n"
    "+new line\n"
    "+another new\n"
    " trailing context\n"
)


class TestCountDiffLines:
    def test_counts_plus_minus_skips_headers(self):
        assert rw.count_diff_lines(DIFF) == 3

    def test_empty(self):
        assert rw.count_diff_lines("") == 0
        assert rw.count_diff_lines(None) == 0


class TestGitlabCompare:
    def test_normalizes_payload(self, monkeypatch):
        payload = {
            "commits": [{}, {}],
            "compare_timeout": False,
            "diffs": [{"new_path": "pkg/auth.go", "diff": DIFF}],
        }
        monkeypatch.setattr(rw, "_glab_api", lambda host, path: {"ok": True, "payload": payload})
        res = rw.gitlab_compare("gitlab.example.com", "g/r", "a" * 40, "main")
        assert res["ok"] and res["ahead_by"] == 2
        assert res["files"] == [{"filename": "pkg/auth.go", "changes": 3}]
        assert not res["truncated"]

    def test_truncated_on_timeout_or_cap(self, monkeypatch):
        payload = {"commits": [], "compare_timeout": True, "diffs": []}
        monkeypatch.setattr(rw, "_glab_api", lambda host, path: {"ok": True, "payload": payload})
        assert rw.gitlab_compare("gitlab.com", "g/r", "a" * 40, "main")["truncated"]

    def test_no_credentials_when_glab_missing(self, monkeypatch):
        monkeypatch.setattr(rw.shutil, "which", lambda name: None)
        res = rw._glab_api("gitlab.example.com", "projects/x")
        assert not res["ok"] and res["kind"] == "no-credentials"


class TestErrorClassification:
    def test_unauthorized_is_no_credentials(self):
        assert rw._classify_stderr("HTTP 401: Unauthorized") == "no-credentials"

    def test_vpn_down_is_unreachable(self):
        for msg in (
            "dial tcp: lookup gitlab.example.com: no such host",
            "connect: connection refused",
            "i/o timeout",
        ):
            assert rw._classify_stderr(msg) == "unreachable"

    def test_other_is_error(self):
        assert rw._classify_stderr("HTTP 500: boom") == "error"


# ---------------------------------------------------------------------------
# fixtures: fake findings.db + report JSONs
# ---------------------------------------------------------------------------

REPOS_DDL = """
CREATE TABLE repos (
  repo_key TEXT PRIMARY KEY, tree TEXT, ownership TEXT,
  business_unit TEXT, label TEXT, product TEXT, repo_dir TEXT,
  base_slug TEXT, ref TEXT, repo_url TEXT, is_branch_audit INTEGER,
  is_md_only INTEGER, preferred TEXT, report_kind TEXT,
  report_path TEXT, audit_date TEXT);
CREATE TABLE open_findings (
  scope_id TEXT, subject_id TEXT, run_id TEXT, finding_id TEXT,
  severity TEXT, validity TEXT, resolution TEXT, family TEXT);
"""

# The contract's open predicate, applied when the fixture inserts: the real
# open_findings view carries only findings not affirmatively closed, not
# false positive, not hardening.
_NON_EXPOSURE = {"false_positive", "hardening"}
_CLOSED = {"resolved", "risk_accepted"}


def _mk_db(tmp_path, repos, findings):
    db = tmp_path / "findings.db"
    con = sqlite3.connect(db)
    con.executescript(REPOS_DDL)
    for r in repos:
        con.execute(
            "INSERT INTO repos (repo_key, tree, ownership, business_unit,"
            " label, repo_dir, base_slug, repo_url, is_branch_audit,"
            " is_md_only, preferred, report_kind, report_path, audit_date)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                r["repo_key"],
                "t",
                "owned",
                "bu",
                "l",
                "d",
                "b",
                r["repo_url"],
                r.get("is_branch_audit", 0),
                0,
                "json",
                r.get("report_kind", "code-audit"),
                r.get("report_path"),
                r.get("audit_date", "2026-07-01"),
            ),
        )
    for f in findings:
        if (f.get("validity") or "confirmed") in _NON_EXPOSURE:
            continue
        if (f.get("resolution") or "open") in _CLOSED:
            continue
        con.execute(
            "INSERT INTO open_findings (scope_id, subject_id, run_id, finding_id,"
            " severity, validity, resolution, family) VALUES ('local',?,?,?,?,?,?,'code')",
            (
                f["repo_key"],
                f"corpus:run:{f['repo_key']}",
                f.get("finding_id", "F-1"),
                f.get("severity", "high"),
                f.get("validity", ""),
                f.get("resolution", "open"),
            ),
        )
    con.commit()
    con.close()
    return db


def _mk_report(tmp_path, name, sha="a" * 40, lines_reviewed=None, companion_lanes=None):
    additional = {"harness_version": "0.0.0-test"}
    if lines_reviewed:
        additional["lines_reviewed"] = lines_reviewed
    if companion_lanes is not None:
        additional["companion_lanes"] = companion_lanes
    metadata = {
        "repository": f"https://github.com/org/{name}",
        "additional": additional,
    }
    if sha is not None:
        metadata["commit"] = f"{sha} (main HEAD, 2026-07-01)"
    p = tmp_path / f"{name}-security-audit.json"
    p.write_text(json.dumps({"metadata": metadata}))
    return p


class TestLoadPopulation:
    def test_head_code_audits_only_and_url_dedupe(self, tmp_path):
        rpt = _mk_report(tmp_path, "r1")
        db = _mk_db(
            tmp_path,
            [
                {
                    "repo_key": "t/a/r1",
                    "repo_url": "https://github.com/o/r1",
                    "report_path": str(rpt),
                    "audit_date": "2026-07-01",
                },
                {
                    "repo_key": "t/b/r1",
                    "repo_url": "https://github.com/o/r1",
                    "report_path": str(rpt),
                    "audit_date": "2026-07-10",
                },
                {
                    "repo_key": "t/a/br",
                    "repo_url": "https://github.com/o/br",
                    "is_branch_audit": 1,
                },
                {
                    "repo_key": "t/a/cc",
                    "repo_url": "https://github.com/o/cc",
                    "report_kind": "cloud-config",
                },
            ],
            [
                # live highs land on the OLDER sibling filing — risk must
                # survive the freshest-audit dedupe (max across siblings)
                {"repo_key": "t/a/r1"},
                {"repo_key": "t/a/r1", "finding_id": "F-2"},
            ],
        )
        pop = rw.load_population(db)
        assert len(pop) == 1
        e = pop[0]
        assert e["repo_key"] == "t/b/r1"  # freshest audit wins
        assert e["sibling_repo_keys"] == ["t/a/r1"]
        assert e["live_crit_high"] == 2

    def test_live_predicate_exclusions(self, tmp_path):
        db = _mk_db(
            tmp_path,
            [
                {"repo_key": "t/a/r", "repo_url": "https://github.com/o/r"},
            ],
            [
                {"repo_key": "t/a/r", "finding_id": "live"},
                {"repo_key": "t/a/r", "finding_id": "hard", "validity": "hardening"},
                {"repo_key": "t/a/r", "finding_id": "fp", "validity": "false_positive"},
                {"repo_key": "t/a/r", "finding_id": "res", "resolution": "resolved"},
                {
                    "repo_key": "t/a/r",
                    "finding_id": "acc",
                    "resolution": "risk_accepted",
                },
                {"repo_key": "t/a/r", "finding_id": "low", "severity": "low"},
                {
                    "repo_key": "t/a/r",
                    "finding_id": "part",
                    "resolution": "partially_resolved",
                },
            ],
        )
        pop = rw.load_population(db)
        assert pop[0]["live_crit_high"] == 2  # live + part


# ---------------------------------------------------------------------------
# events (rule 1)
# ---------------------------------------------------------------------------


class TestEvents:
    def test_load_skips_consumed_and_junk(self, tmp_path):
        p = tmp_path / "rescan-events.jsonl"
        p.write_text(
            json.dumps({"source": "external-report", "repo": "x", "consumed": False})
            + "\n"
            + json.dumps({"source": "cve", "repo": "y", "consumed": True})
            + "\n"
            + "not json\n"
            + json.dumps({"source": "unknown-kind", "repo": "z"})
            + "\n"
        )
        evs = rw.load_events(p)
        assert [e["source"] for e in evs] == ["external-report"]

    def test_absent_file(self, tmp_path):
        assert rw.load_events(tmp_path / "nope.jsonl") == []

    def test_lanes_per_source(self):
        assert rw.event_lane("external-report", "P2") == "full-audit+validate"
        assert rw.event_lane("methodology", "P0") == "full-audit"
        assert rw.event_lane("methodology", "P1") is None
        assert rw.event_lane("cve", "P3") == "impact-lane"
        assert rw.event_lane("release", None) == "release-passthrough"


# ---------------------------------------------------------------------------
# budget guard
# ---------------------------------------------------------------------------


def _dec(tier, lane, event=None, C=0):
    d = {
        "repo_key": f"k/{tier}/{lane}/{C}",
        "repo_url": "u",
        "tier": tier,
        "lane": lane,
        "C": C,
    }
    if event:
        d["event_source"] = event
    return d


class TestBudget:
    def test_no_budget_keeps_all(self):
        decs = [_dec("P0", "full-audit"), _dec("P2", "full-audit")]
        kept, dropped = rw.apply_budget(decs, 30.0, None)
        assert kept == decs and dropped == []

    def test_drops_lowest_tier_first_and_lists(self):
        decs = [
            _dec("P0", "full-audit", C=9000),
            _dec("P1", "full-audit", C=8000),
            _dec("P3", "full-audit", C=100),
            _dec("P2", "diff-scan"),
        ]
        kept, dropped = rw.apply_budget(decs, 10.0, 25.0)
        assert [d["tier"] for d in dropped] == ["P3"]
        assert "budget" in dropped[0]["dropped_reason"]
        assert len([d for d in kept if d["lane"] == "full-audit"]) == 2
        # non-full lanes never touched
        assert any(d["lane"] == "diff-scan" for d in kept)

    def test_event_rows_never_dropped(self):
        decs = [
            _dec("P2", "full-audit+validate", event="external-report"),
            _dec("P3", "full-audit"),
        ]
        kept, dropped = rw.apply_budget(decs, 10.0, 10.0)
        assert [d["tier"] for d in dropped] == ["P3"]
        assert any(d.get("event_source") for d in kept)


# ---------------------------------------------------------------------------
# end-to-end main() — fake db + reports, patched fetchers, no network
# ---------------------------------------------------------------------------


class TestMainEndToEnd:
    def _setup(self, tmp_path):
        r1 = _mk_report(tmp_path, "hot")  # will churn past rule-2
        r2 = _mk_report(tmp_path, "quiet")  # unchanged
        r3 = _mk_report(tmp_path, "evt")  # event target
        repos = [
            {
                "repo_key": "t/p/hot",
                "repo_url": "https://github.com/o/hot",
                "report_path": str(r1),
                "audit_date": "2026-07-01",
            },
            {
                "repo_key": "t/p/quiet",
                "repo_url": "https://github.com/o/quiet",
                "report_path": str(r2),
                "audit_date": "2026-07-01",
            },
            {
                "repo_key": "t/p/evt",
                "repo_url": "https://github.com/o/evt",
                "report_path": str(r3),
                "audit_date": "2026-07-01",
            },
            {
                "repo_key": "t/p/nosha",
                "repo_url": "https://github.com/o/nosha",
                "report_path": str(_mk_report(tmp_path, "nosha", sha=None)),
                "audit_date": "2026-07-01",
            },
            {
                "repo_key": "t/p/nosha-quiet",
                "repo_url": "https://github.com/o/nosha-quiet",
                "report_path": str(_mk_report(tmp_path, "nosha-quiet", sha=None)),
                "audit_date": "2026-07-01",
            },
            {
                "repo_key": "t/p/gl",
                "repo_url": "https://gitlab.example.com/grp/sub/gl",
                "report_path": None,
                "audit_date": "2026-07-01",
            },
            {
                "repo_key": "t/p/odd",
                "repo_url": "https://svn.example.com/o/odd",
                "report_path": None,
                "audit_date": "2026-07-01",
            },
        ]
        findings = [{"repo_key": "t/p/hot"}]  # P1
        db = _mk_db(tmp_path, repos, findings)
        events = tmp_path / "rescan-events.jsonl"
        events.write_text(
            json.dumps(
                {
                    "source": "external-report",
                    "repo": "https://github.com/o/evt",
                    "refs": [],
                    "note": "researcher report",
                    "date": "2026-07-26",
                    "consumed": False,
                }
            )
            + "\n"
        )
        return db, events

    def _patch_network(self, monkeypatch, quota=100_000):
        monkeypatch.setattr(rw, "gh_rate_remaining", lambda: quota)

        def fake_gh_info(project):
            if project == "o/nosha-quiet":  # push predates the audit
                return {
                    "ok": True,
                    "pushed_at": "2026-06-01T00:00:00Z",
                    "archived": False,
                    "default_branch": "main",
                }
            return {
                "ok": True,
                "pushed_at": "2026-07-25T00:00:00Z",
                "archived": False,
                "default_branch": "main",
            }

        def fake_gh_cmp(project, sha):
            if project == "o/hot":
                return {
                    "ok": True,
                    "ahead_by": 40,
                    "truncated": False,
                    "files": [{"filename": "pkg/a.go", "changes": 9000}],
                }
            return {"ok": True, "ahead_by": 0, "truncated": False, "files": []}

        def fake_gl_info(host, project):
            return {
                "ok": False,
                "kind": "unreachable",
                "error": "dial tcp: i/o timeout",
            }

        monkeypatch.setattr(rw, "gh_repo_info", fake_gh_info)
        monkeypatch.setattr(rw, "gh_compare", fake_gh_cmp)
        monkeypatch.setattr(rw, "gitlab_repo_info", fake_gl_info)

    def test_full_run(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(["--db", str(db), "--events", str(events), "--out", str(out)])
        assert rc == 0
        doc = json.loads(out.read_text())
        assert out.with_suffix(".md").is_file()

        by_key = {d["repo_key"]: d for d in doc["decisions"]}
        # event row is FIRST, ahead of the table
        assert doc["decisions"][0]["repo_key"] == "t/p/evt"
        assert doc["decisions"][0]["lane"] == "full-audit+validate"
        assert doc["decisions"][0]["event_source"] == "external-report"
        # rule-2 churn -> full-audit
        assert by_key["t/p/hot"]["lane"] == "full-audit"
        assert by_key["t/p/hot"]["rule"] == "rule-2"
        # zero-diff -> rule-6 noise
        assert by_key["t/p/quiet"]["lane"] == "none"
        assert by_key["t/p/quiet"]["rule"] == "rule-6"
        # no-pinned-sha: fail-safe self-heal branch — push signal ->
        # full audit; no push signal -> none with the honest reason
        assert by_key["t/p/nosha"]["lane"] == "full-audit"
        assert by_key["t/p/nosha"]["rule"] == "no-pinned-sha"
        assert "self-healing" in by_key["t/p/nosha"]["reason"]
        # ...but with no push signal the repo never reaches stage 2, so
        # its sha-lessness is irrelevant until it changes (rule-7 none)
        assert by_key["t/p/nosha-quiet"]["lane"] == "none"
        assert by_key["t/p/nosha-quiet"]["rule"] == "rule-7"
        # gitlab unreachable + unsupported host: listed, never dropped
        assert by_key["t/p/gl"]["status"] == "unreachable"
        assert by_key["t/p/odd"]["status"] == "unsupported-host"
        assert doc["population"]["unreachable"] == 1
        assert doc["population"]["gitlab_unreachable"] == 1
        assert doc["population"]["unsupported_host"] == 1
        assert doc["events_honored"][0]["queued"] is True
        # VPN-down visibility in the MD summary
        assert "unreachable" in out.with_suffix(".md").read_text()

    def test_budget_drop_listed(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch)
        out = tmp_path / "out" / "rescan-worklist.json"
        # budget fits ONE full at unit cost 10: the event full-audit
        # survives, the table-routed one is dropped and listed
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--unit-cost-full",
                "10",
                "--monthly-budget",
                "10",
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        # two table-routed fulls (nosha self-heal P2 + hot P1) exceed the
        # budget: both dropped, lowest tier first; the event row survives
        assert len(doc["dropped_for_budget"]) == 2
        assert doc["dropped_for_budget"][0]["repo_key"] == "t/p/nosha"
        assert doc["dropped_for_budget"][1]["repo_key"] == "t/p/hot"
        assert any(d.get("event_source") for d in doc["decisions"])

    def test_rate_limit_preflight_refuses(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch, quota=1)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(["--db", str(db), "--events", str(events), "--out", str(out)])
        assert rc == 4  # refused: quota-starved run would emit
        assert not out.exists()  # a legitimate-looking garbage worklist

    def test_rate_limit_override_proceeds(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch, quota=1)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--ignore-rate-limit",
            ]
        )
        assert rc == 0
        assert out.exists()

    def test_stage2_quota_deferral(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch)
        # first call = stage-1 preflight (plenty), second = stage-2
        # remaining (fits only 1 GitHub compare)
        quotas = iter([100_000, 1])
        monkeypatch.setattr(rw, "gh_rate_remaining", lambda: next(quotas, 100_000))
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(["--db", str(db), "--events", str(events), "--out", str(out)])
        assert rc == 0
        doc = json.loads(out.read_text())
        deferred = [d for d in doc["decisions"] if d["status"] == "quota-deferred"]
        assert deferred, "some compares must be quota-deferred"
        assert all(d["lane"] == "none" and d["rule"] == "quota-deferred" for d in deferred)
        assert "quota-deferred" in out.with_suffix(".md").read_text()

    def test_rate_limit_unknown_proceeds(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch, quota=None)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(["--db", str(db), "--events", str(events), "--out", str(out)])
        assert rc == 0  # undeterminable quota: stage 1 surfaces per-repo

    def test_no_network_run(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--no-network",
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        assert doc["network"] is False
        assert doc["population"]["stage1_candidates"] == 0
        # offline: nothing hits churn rules; recent audits -> none
        table = [d for d in doc["decisions"] if not d.get("event_source")]
        assert all(d["lane"] == "none" for d in table)


# ---------------------------------------------------------------------------
# session 4 levers 1+2 — exposure classes, tripwire, trickle-drain
# ---------------------------------------------------------------------------


class TestExposureClass:
    def test_public_defaults_to_public_external(self):
        # public ~= productized in this portfolio: no designation needed
        assert rw.exposure_class({"visibility": "public"}) == "public-external"

    def test_internal_tooling_designation_demotes_public(self):
        assert (
            rw.exposure_class({"visibility": "public", "designation": "internal-tooling"})
            == "public-internal"
        )

    def test_private_external_designation(self):
        # externality = curated repository exposure designation,
        # NOT the corpus ownership/BU tag
        assert (
            rw.exposure_class({"visibility": "private", "designation": "external"})
            == "private-external"
        )
        assert (
            rw.exposure_class({"visibility": "private", "ownership": "external-bu"})
            == "private-internal"
        )

    def test_public_upstream_elevates_visibility_axis(self):
        # undesignated private fork of a public upstream -> rank 3
        # (must NOT ride the public~=productized default)
        assert (
            rw.exposure_class({"visibility": "private", "fork": True, "parent": "up/stream"})
            == "public-internal"
        )
        # externally designated + upstream -> rank 1
        assert (
            rw.exposure_class(
                {
                    "visibility": "private",
                    "designation": "external",
                    "fork": True,
                    "parent": "up/stream",
                }
            )
            == "public-external"
        )

    def test_private_internal_baseline(self):
        assert rw.exposure_class({"visibility": "internal"}) == "private-internal"
        assert rw.exposure_class({}) == "private-internal"

    def test_fork_without_parent_not_elevated(self):
        assert rw.exposure_class({"visibility": "private", "fork": True}) == "private-internal"


class TestDesignations:
    def test_load_and_lookup(self, tmp_path):
        f = tmp_path / "exposure-designations.json"
        f.write_text(
            json.dumps(
                {
                    "designations": [
                        {
                            "match": "https://github.com/org/repo",
                            "exposure": "external",
                            "note": "customer service",
                        },
                        {
                            "match": "https://github.com/tools-org/",
                            "exposure": "internal-tooling",
                        },
                        {"match": "https://x/y", "exposure": "bogus-value"},
                    ]
                }
            )
        )
        d = rw.load_designations(f)
        assert len(d) == 2  # bogus exposure value dropped
        assert rw.lookup_designation("https://github.com/org/repo", d) == "external"
        assert rw.lookup_designation("https://github.com/org/repo-two", d) is None  # exact only
        assert (
            rw.lookup_designation("https://github.com/tools-org/anything", d) == "internal-tooling"
        )  # prefix
        assert rw.lookup_designation(None, d) is None

    def test_missing_file_is_empty(self, tmp_path):
        assert rw.load_designations(tmp_path / "nope.json") == []


class TestTightenedCeilings:
    def test_external_band_p1_tightens_to_180(self):
        for exp in ("public-external", "private-external"):
            ctx = {"tier": "P1", "exposure": exp, "audit_age_days": 200}
            assert rw._over_ceiling(ctx) is True  # 270 -> 180

    def test_internal_band_p1_keeps_270(self):
        for exp in ("public-internal", "private-internal"):
            ctx = {"tier": "P1", "exposure": exp, "audit_age_days": 200}
            assert rw._over_ceiling(ctx) is False

    def test_private_external_p2_tightens_to_270(self):
        ctx = {"tier": "P2", "exposure": "private-external", "audit_age_days": 300}
        assert rw._over_ceiling(ctx) is True  # 365 -> 270


class TestTripwire:
    def _rows_and_keys(self):
        rows = [
            {
                "repo_key": "k/gh",
                "lane": "diff-scan-quarterly",
                "rule": "rule-5",
                "reason": "below-threshold",
                "C": 100,
            },
            {
                "repo_key": "k/gl",
                "lane": "deps-lane",
                "rule": "rule-3b",
                "reason": "deps only",
                "C": 10,
            },
            {
                "repo_key": "k/full",
                "lane": "full-audit",
                "rule": "rule-2",
                "reason": "churn",
                "C": 9000,
            },
        ]
        by_key = {
            "k/gh": {"host_kind": "github", "project": "o/gh", "pinned_sha": "a" * 40},
            "k/gl": {"host_kind": "gitlab", "_patch": "+password=x"},
            "k/full": {
                "host_kind": "github",
                "project": "o/full",
                "pinned_sha": "b" * 40,
            },
        }
        return rows, by_key

    def test_hit_escalates_below_threshold_rows_only(self, monkeypatch):
        monkeypatch.setattr(rw.shutil, "which", lambda _: "/bin/gitleaks")
        rows, by_key = self._rows_and_keys()
        stats = rw.run_tripwire(
            rows,
            by_key,
            jobs=2,
            gh_patch=lambda proj, sha: "+aws_secret=AKIA",
            leak_scan=lambda patch: 2 if patch else None,
            rate_remaining=lambda: 100_000,
        )
        assert stats["eligible"] == 2 and stats["escalated"] == 2
        assert rows[0]["lane"] == "diff-scan"
        assert rows[0]["rule"] == "tripwire"
        assert rows[0]["tripwire"] == {"gitleaks": 2}
        assert "was rule" not in rows[0]["reason"]  # original reason kept
        assert rows[1]["lane"] == "diff-scan"  # gitlab patch reused
        assert rows[2]["lane"] == "full-audit"  # never touched

    def test_no_hits_no_escalation(self, monkeypatch):
        monkeypatch.setattr(rw.shutil, "which", lambda _: "/bin/gitleaks")
        rows, by_key = self._rows_and_keys()
        stats = rw.run_tripwire(
            rows,
            by_key,
            jobs=2,
            gh_patch=lambda proj, sha: "+harmless()",
            leak_scan=lambda patch: 0,
            rate_remaining=lambda: 100_000,
        )
        assert stats["escalated"] == 0
        assert rows[0]["lane"] == "diff-scan-quarterly"

    def test_scanner_missing_records_and_skips(self, monkeypatch):
        monkeypatch.setattr(rw.shutil, "which", lambda _: None)
        rows, by_key = self._rows_and_keys()
        stats = rw.run_tripwire(rows, by_key, jobs=2)
        assert stats["scanner_unavailable"] == 2
        assert rows[0]["lane"] == "diff-scan-quarterly"

    def test_quota_short_skips_github_fetches(self, monkeypatch):
        monkeypatch.setattr(rw.shutil, "which", lambda _: "/bin/gitleaks")
        rows, by_key = self._rows_and_keys()
        stats = rw.run_tripwire(
            rows,
            by_key,
            jobs=2,
            gh_patch=lambda proj, sha: (_ for _ in ()).throw(
                AssertionError("must not fetch when quota short")
            ),
            leak_scan=lambda patch: 1 if patch else None,
            rate_remaining=lambda: 0,
        )
        assert stats["quota_skipped"] == 1  # the one github row
        assert rows[0]["lane"] == "diff-scan-quarterly"
        assert rows[1]["lane"] == "diff-scan"  # gitlab row still swept


class TestPreroute:
    def _rows_and_keys(self):
        rows = [
            {
                "repo_key": "k/big",
                "lane": "diff-scan-quarterly",
                "rule": "rule-5",
                "reason": "rule-5: below-threshold",
                "C": 640,
            },
            {
                "repo_key": "k/trunc",
                "lane": "diff-scan",
                "rule": "rule-3",
                "reason": "rule-3: sensitive",
                "C": 300,
                "truncated": True,
            },
            {
                "repo_key": "k/small",
                "lane": "diff-scan-quarterly",
                "rule": "rule-5",
                "reason": "rule-5: below-threshold",
                "C": 40,
            },
            {
                "repo_key": "k/gl",
                "lane": "diff-scan-quarterly",
                "rule": "rule-5",
                "reason": "rule-5: below-threshold",
                "C": 200,
            },
            {
                "repo_key": "k/full",
                "lane": "full-audit",
                "rule": "rule-2",
                "reason": "rule-2: churn",
                "C": 9000,
            },
        ]
        by_key = {
            "k/big": {
                "host_kind": "github",
                "project": "o/big",
                "default_branch": "main",
                "fp_files": 28,
            },
            "k/trunc": {
                "host_kind": "github",
                "project": "o/trunc",
                "default_branch": "main",
                "fp_files": 300,
            },
            "k/small": {
                "host_kind": "github",
                "project": "o/small",
                "default_branch": "main",
                "fp_files": 3,
            },
            "k/gl": {"host_kind": "gitlab", "project": "g/gl", "fp_files": 40},
            "k/full": {
                "host_kind": "github",
                "project": "o/full",
                "default_branch": "main",
                "fp_files": 500,
            },
        }
        return rows, by_key

    def test_truncated_rerouted_without_api_cost(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: {
                "ok": True,
                "fp_files": 10_000,
                "truncated": False,
            },
            rate_remaining=lambda: 100_000,
        )
        assert stats["rerouted_truncated"] == 1
        assert rows[1]["lane"] == "full-audit"
        assert rows[1]["rule"] == "rule-3+preroute"
        assert "was rule-3" in rows[1]["reason"]

    def test_ratio_over_30pct_rerouted(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            # amd-ci shape: 28 of 72 first-party files changed (39%)
            tree_count=lambda p, r: {"ok": True, "fp_files": 72, "truncated": False},
            rate_remaining=lambda: 100_000,
        )
        assert stats["rerouted_ratio"] == 1
        assert rows[0]["lane"] == "full-audit"
        assert rows[0]["preroute"] == {
            "changed_first_party_files": 28,
            "total_first_party_files": 72,
        }

    def test_ratio_under_30pct_untouched(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: {"ok": True, "fp_files": 1000, "truncated": False},
            rate_remaining=lambda: 100_000,
        )
        assert stats["rerouted_ratio"] == 0
        assert rows[0]["lane"] == "diff-scan-quarterly"

    def test_small_changes_skip_tree_fetch(self):
        rows, by_key = self._rows_and_keys()
        fetched = []
        rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: (
                fetched.append(p) or {"ok": True, "fp_files": 1000, "truncated": False}
            ),
            rate_remaining=lambda: 100_000,
        )
        # fp_files=3 meets the floor but k/small sorts below the
        # 2-week imminent horizon (lowest C of the quarterly rows)
        assert "o/small" not in fetched
        assert "o/full" not in fetched  # already full-audit

    def test_tree_failure_counted_not_silent(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: {"ok": False, "error": "rate limit"},
            rate_remaining=lambda: 100_000,
        )
        assert stats["tree_failed"] == 1  # k/big
        assert stats["checked_ratio"] == 0
        assert rows[0]["lane"] == "diff-scan-quarterly"
        assert rows[0]["preroute_tree_error"].startswith("rate limit")

    def test_gitlab_rows_skipped_and_counted(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: {"ok": True, "fp_files": 50, "truncated": False},
            rate_remaining=lambda: 100_000,
        )
        assert stats["gitlab_unchecked"] == 1
        assert rows[3]["lane"] == "diff-scan-quarterly"

    def test_truncated_tree_leaves_row(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: {"ok": True, "fp_files": 0, "truncated": True},
            rate_remaining=lambda: 100_000,
        )
        assert stats["rerouted_ratio"] == 0
        assert rows[0]["lane"] == "diff-scan-quarterly"

    def test_quota_short_skips_tree_fetches(self):
        rows, by_key = self._rows_and_keys()
        stats = rw.run_preroute(
            rows,
            by_key,
            jobs=2,
            tree_count=lambda p, r: (_ for _ in ()).throw(
                AssertionError("must not fetch when quota short")
            ),
            rate_remaining=lambda: 0,
        )
        assert stats["quota_skipped"] == 1  # k/big, the one gh cand
        assert rows[0]["lane"] == "diff-scan-quarterly"


class TestDrainAndExposureEndToEnd(TestMainEndToEnd):
    def test_worklist_carries_exposure_and_drain(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        self._patch_network(monkeypatch)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--no-tripwire",
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        assert set(doc["summary"]["exposure"]) == set(rw.EXPOSURE_ORDER)
        for d in doc["decisions"]:
            if not d.get("event_source"):
                assert d["exposure"] in rw.EXPOSURE_ORDER
        assert doc["summary"]["tripwire"].get("disabled") is True
        drain = doc["summary"]["drain"]
        pool = [d for d in doc["decisions"] if d["lane"] == "diff-scan-quarterly"]
        assert drain["pool"] == len(pool)
        if pool:
            assert [d["drain_order"] for d in pool] == list(range(len(pool)))

    def test_public_sorts_ahead_within_lane(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)

        def fake_gh_info(project):
            vis = "public" if project == "o/quiet" else "private"
            return {
                "ok": True,
                "pushed_at": "2026-07-25T00:00:00Z",
                "archived": False,
                "default_branch": "main",
                "visibility": vis,
                "fork": False,
                "parent": None,
            }

        def fake_gh_cmp(project, sha):
            return {
                "ok": True,
                "ahead_by": 3,
                "truncated": False,
                "files": [{"filename": "pkg/a.go", "changes": 50}],
            }

        monkeypatch.setattr(rw, "gh_rate_remaining", lambda: 100_000)
        monkeypatch.setattr(rw, "gh_repo_info", fake_gh_info)
        monkeypatch.setattr(rw, "gh_compare", fake_gh_cmp)
        monkeypatch.setattr(
            rw,
            "gitlab_repo_info",
            lambda h, p: {"ok": False, "kind": "unreachable", "error": "x"},
        )
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--no-tripwire",
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        pool = [d for d in doc["decisions"] if d["lane"] == "diff-scan-quarterly"]
        assert len(pool) >= 2
        assert pool[0]["repo_url"].endswith("/quiet")  # public first
        assert pool[0]["exposure"] == "public-external"


class TestTripwireByteSafety:
    def test_gh_patch_tolerates_invalid_utf8(self, monkeypatch):
        # observed live: a 28MB compare diff with invalid UTF-8 crashed
        # the text-mode pipe — bytes + tolerant decode must survive
        class P:
            returncode = 0
            stdout = b"+password=x \xff\xfe broken bytes"

        monkeypatch.setattr(rw.subprocess, "run", lambda *a, **k: P())
        patch = rw.gh_compare_patch("o/r", "a" * 40)
        assert patch is not None and "+password=x" in patch


class TestNeverAuditedBootstrap:
    """Lever 1d: cadence rule 1 implemented — inventory repos without
    baselines become full-audit+bootstrap rows (operator directive
    2026-07-28)."""

    def _graph(self, tmp_path, repo_ids):
        g = tmp_path / "portfolio-graph.db"
        con = sqlite3.connect(g)
        con.execute("CREATE TABLE nodes (id TEXT, kind TEXT, label TEXT, attrs TEXT)")
        con.executemany(
            "INSERT INTO nodes VALUES (?,?,?,?)",
            [(r, "repo", r, "{}") for r in repo_ids],
        )
        con.commit()
        con.close()
        return g

    def test_missing_baseline_emits_rule1_row(self, tmp_path):
        g = self._graph(tmp_path, ["repo:github.com/org/newrepo", "repo:github.com/org/audited"])
        rows = rw.never_audited_rows(g, {"https://github.com/org/audited"}, [])
        assert len(rows) == 1
        r = rows[0]
        assert r["rule"] == "rule-1-bootstrap"
        assert r["lane"] == "full-audit"
        assert r["status"] == "never-audited"
        assert r["repo_url"] == "https://github.com/org/newrepo"
        assert r["exposure"] == "private-internal"  # no API call: default

    def test_designation_elevates_exposure(self, tmp_path):
        g = self._graph(tmp_path, ["repo:github.com/org/svc-backend"])
        rows = rw.never_audited_rows(g, set(), [("https://github.com/org/svc-backend", "external")])
        assert rows[0]["exposure"] == "private-external"

    def test_missing_graph_db_is_empty(self, tmp_path):
        assert rw.never_audited_rows(tmp_path / "nope.db", set(), []) == []

    def test_end_to_end_row_and_md(self, tmp_path, monkeypatch):
        # reuse the e2e fixture; add a graph with one unaudited repo
        helper = TestMainEndToEnd()
        db, events = helper._setup(tmp_path)
        helper._patch_network(monkeypatch)
        g = self._graph(tmp_path, ["repo:github.com/org/brand-new"])
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--graph-db",
                str(g),
                "--no-tripwire",
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        boot = [d for d in doc["decisions"] if d["rule"] == "rule-1-bootstrap"]
        assert len(boot) == 1
        assert doc["population"]["never_audited"] == 1
        assert "never-audited inventory repo" in out.with_suffix(".md").read_text()

    def test_no_bootstrap_flag(self, tmp_path, monkeypatch):
        helper = TestMainEndToEnd()
        db, events = helper._setup(tmp_path)
        helper._patch_network(monkeypatch)
        g = self._graph(tmp_path, ["repo:github.com/org/brand-new"])
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(
            [
                "--db",
                str(db),
                "--events",
                str(events),
                "--out",
                str(out),
                "--graph-db",
                str(g),
                "--no-tripwire",
                "--no-bootstrap",
            ]
        )
        assert rc == 0
        doc = json.loads(out.read_text())
        assert doc["population"]["never_audited"] == 0
        assert not [d for d in doc["decisions"] if d["rule"] == "rule-1-bootstrap"]


class TestBanBreaker:
    """Secondary-ban circuit breaker: quota reads fine while every call
    403s (measured 2026-07-28: most of a sweep's calls errored while the
    quota read healthy)."""

    def test_streak_trips_and_success_resets(self):
        b = rw._BanBreaker(threshold=3)
        b.record(False)
        b.record(False)
        assert not b.tripped
        b.record(True)  # success resets
        b.record(False)
        b.record(False)
        b.record(False)
        assert b.tripped

    def test_stage1_aborts_after_streak(self, monkeypatch):
        calls = {"n": 0}

        def failing_gh(project):
            calls["n"] += 1
            return {"ok": False, "kind": "error", "error": "403 abuse"}

        monkeypatch.setattr(rw, "BAN_STREAK_THRESHOLD", 5)
        entries = [{"repo_url": f"https://github.com/o/r{i}"} for i in range(40)]
        rw.stage1(entries, jobs=1, gh_info=failing_gh)
        skipped = [e for e in entries if e["status"] == "ban-suspected"]
        assert calls["n"] <= 6  # stopped calling after the trip
        assert len(skipped) >= 30  # remainder skipped, not churned
        assert all("secondary ban" in e["error"] for e in skipped)


def test_change_metrics_counts_iac_files():
    m = rw.change_metrics(
        [
            {"filename": "infra/main.tf", "changes": 10},
            {"filename": "cloudformation/stack.yaml", "changes": 5},
            {
                "filename": "openshift/backend.template.yaml",
                "changes": 3,
            },  # OpenShift Template != CFN
            {"filename": "vendor/x/mod.tf", "changes": 9},  # third-party
            {"filename": "src/main.go", "changes": 100},
        ]
    )
    assert m["iac_files"] == 2


def test_iac_rows_additive_baseline_split():
    entries = [
        {
            "repo_key": "a",
            "repo_url": "https://github.com/o/a",
            "status": "ok",
            "iac_files": 3,
            "sibling_repo_keys": [],
        },
        {
            "repo_key": "b",
            "repo_url": "https://github.com/o/b",
            "status": "ok",
            "iac_files": 1,
            "sibling_repo_keys": [],
        },
        {
            "repo_key": "c",
            "repo_url": "https://github.com/o/c",
            "status": "ok",
            "iac_files": 0,
            "sibling_repo_keys": [],
        },
        {
            "repo_key": "d",
            "repo_url": "https://github.com/o/d",
            "status": "quota-deferred",
            "iac_files": 2,
            "sibling_repo_keys": [],
        },
    ]
    rows = rw.iac_rows(entries, {"https://github.com/o/a"})
    lanes = {r["repo_key"]: r["lane"] for r in rows}
    assert lanes == {"a": "iac-lane", "b": "iac-baseline"}
    assert all(r["rule"] == "lever-6" for r in rows)


def test_report_meta_carries_companion_lanes(tmp_path):
    stamped = _mk_report(tmp_path, "st", companion_lanes=["cloud-config-audit", 7])
    sha, loc, companions = rw._report_meta(str(stamped))
    assert companions == ["cloud-config-audit"]  # non-strings dropped
    # absent stamp -> [] (and the legacy fields keep working)
    plain = _mk_report(tmp_path, "pl", lines_reviewed=1234)
    sha, loc, companions = rw._report_meta(str(plain))
    assert (sha, loc, companions) == ("a" * 40, 1234, [])
    # junk stamp type -> []
    junk = _mk_report(tmp_path, "jk", companion_lanes="cloud-config-audit")
    assert rw._report_meta(str(junk))[2] == []


def test_companion_rows_backfill_only_where_needed():
    """lever-6-companion: stamp + no baseline + no iac row this run ->
    additive iac-baseline row; every other combination emits nothing."""
    entries = [
        {
            "repo_key": "a",
            "repo_url": "https://github.com/o/a",
            "status": "network-skipped",
            "companion_lanes": ["cloud-config-audit"],
        },  # -> row
        {
            "repo_key": "b",
            "repo_url": "https://github.com/o/b",
            "status": "ok",
            "companion_lanes": ["cloud-config-audit"],
        },  # has baseline
        {
            "repo_key": "c",
            "repo_url": "https://github.com/o/c",
            "status": "ok",
            "companion_lanes": ["cloud-config-audit"],
        },  # iac row already
        {
            "repo_key": "d",
            "repo_url": "https://github.com/o/d",
            "status": "ok",
            "companion_lanes": [],
        },  # unstamped
        {
            "repo_key": "e",
            "repo_url": None,
            "companion_lanes": ["cloud-config-audit"],
        },  # no URL
    ]
    rows = rw.companion_rows(entries, {"https://github.com/o/b"}, {"https://github.com/o/c"})
    assert [r["repo_key"] for r in rows] == ["a"]
    row = rows[0]
    assert row["lane"] == "iac-baseline"
    assert row["rule"] == "lever-6-companion"
    assert "companion_lanes" in row["reason"]
    assert row["tier"] is None  # additive, untiered


class TestCompanionBackfillEndToEnd(TestMainEndToEnd):
    def test_stamped_repo_gets_companion_row(self, tmp_path, monkeypatch):
        """A quiet repo whose latest report stamps companion_lanes gets
        an ADDITIVE iac-baseline row (rule lever-6-companion) — and the
        tier-None row survives the decisions sort."""
        db, events = self._setup(tmp_path)
        stamped = _mk_report(tmp_path, "iacq", companion_lanes=["cloud-config-audit"])
        con = sqlite3.connect(db)
        con.execute(
            "INSERT INTO repos (repo_key, repo_url, report_path,"
            " audit_date, report_kind, is_branch_audit) VALUES"
            " (?,?,?,?,?,?)",
            (
                "t/p/iacq",
                "https://github.com/o/iacq",
                str(stamped),
                "2026-07-01",
                "code-audit",
                0,
            ),
        )
        con.commit()
        con.close()
        self._patch_network(monkeypatch)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(["--db", str(db), "--events", str(events), "--out", str(out)])
        assert rc == 0
        doc = json.loads(out.read_text())
        companion = [d for d in doc["decisions"] if d["rule"] == "lever-6-companion"]
        assert len(companion) == 1
        assert companion[0]["repo_key"] == "t/p/iacq"
        assert companion[0]["lane"] == "iac-baseline"
        # additive: the table's own decision for the repo still exists
        table = [
            d
            for d in doc["decisions"]
            if d["repo_key"] == "t/p/iacq" and d["rule"] != "lever-6-companion"
        ]
        assert len(table) == 1

    def test_no_companion_row_when_baseline_exists(self, tmp_path, monkeypatch):
        db, events = self._setup(tmp_path)
        stamped = _mk_report(tmp_path, "iacq", companion_lanes=["cloud-config-audit"])
        con = sqlite3.connect(db)
        con.execute(
            "INSERT INTO repos (repo_key, repo_url, report_path,"
            " audit_date, report_kind, is_branch_audit) VALUES"
            " (?,?,?,?,?,?)",
            (
                "t/p/iacq",
                "https://github.com/o/iacq",
                str(stamped),
                "2026-07-01",
                "code-audit",
                0,
            ),
        )
        # the same repo already carries a cloud-config baseline
        con.execute(
            "INSERT INTO repos (repo_key, repo_url, report_path,"
            " audit_date, report_kind, is_branch_audit) VALUES"
            " (?,?,?,?,?,?)",
            (
                "t/p/iacq-cc",
                "https://github.com/o/iacq",
                None,
                "2026-07-02",
                "cloud-config",
                0,
            ),
        )
        con.commit()
        con.close()
        self._patch_network(monkeypatch)
        out = tmp_path / "out" / "rescan-worklist.json"
        rc = rw.main(["--db", str(db), "--events", str(events), "--out", str(out)])
        assert rc == 0
        doc = json.loads(out.read_text())
        assert not [d for d in doc["decisions"] if d["rule"] == "lever-6-companion"]


# ---------------------------------------------------------------------------
# threat-model re-model cadence (plan Phases 1-3, shipped 2026-08-05)
# ---------------------------------------------------------------------------


def _write_model(d: Path, repo: str, date_str: str | None, trailing_sections: int = 0) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    body = f"# Threat Model: {repo}\n\n## 1. System context\n\nx\n"
    if date_str:
        body += (
            f"\n## 7. Provenance\n\n- mode: bootstrap\n"
            f"- date: {date_str}\n"
            f"- target: https://github.com/o/{repo} @ abc1234\n"
        )
    for i in range(trailing_sections):
        body += f"\n## {8 + i}. Extra {i}\n\n" + ("filler line\n" * 400)
    p = d / f"{repo}-threat-model.md"
    p.write_text(body, encoding="utf-8")
    return p


class TestThreatModelResolution:
    def test_companion_beside_audit_report(self, tmp_path):
        _write_model(tmp_path, "repo1", "2026-01-01")
        got = rw.threat_model_path(str(tmp_path / "repo1-security-audit.json"))
        assert got == tmp_path / "repo1-threat-model.md"

    def test_branch_suffixed_copies_are_not_the_head_model(self, tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "repo1__release-4.22-threat-model.md").write_text("x")
        assert rw.threat_model_path(str(tmp_path / "repo1-security-audit.json")) is None

    def test_single_loose_model_is_accepted(self, tmp_path):
        _write_model(tmp_path, "othername", "2026-01-01")
        assert rw.threat_model_path(str(tmp_path / "repo1-security-audit.json")) is not None

    def test_ambiguous_loose_models_refuse_to_guess(self, tmp_path):
        _write_model(tmp_path, "one", "2026-01-01")
        _write_model(tmp_path, "two", "2026-01-01")
        assert rw.threat_model_path(str(tmp_path / "repo1-security-audit.json")) is None

    def test_no_report_path(self):
        assert rw.threat_model_path(None) is None


class TestReadModelDate:
    def test_reads_provenance_date(self, tmp_path):
        p = _write_model(tmp_path, "r", "2026-03-04")
        assert rw.read_model_date(p) == __import__("datetime").date(2026, 3, 4)

    def test_tail_read_falls_back_for_long_trailing_sections(self, tmp_path):
        """Provenance is section 7, but sections 8-10 are optional and
        can push it far outside the tail window. The full-read fallback
        is what keeps those models visible to the backstop."""
        p = _write_model(tmp_path, "r", "2026-03-04", trailing_sections=3)
        assert p.stat().st_size > rw._TM_TAIL_BYTES
        assert rw.read_model_date(p) == __import__("datetime").date(2026, 3, 4)

    def test_undated_model(self, tmp_path):
        p = _write_model(tmp_path, "r", None)
        assert rw.read_model_date(p) is None

    def test_missing_file(self, tmp_path):
        assert rw.read_model_date(tmp_path / "nope.md") is None


class TestThreatModelSurfaceMatcher:
    @pytest.mark.parametrize(
        "path",
        [
            "cmd/manager/main.go",
            "pkg/api/v1/types.go",
            "internal/handlers/auth.go",
            "webhook/validating.go",
            "api/openapi-spec/swagger.json",
            "proto/svc.proto",
            "pkg/server/listen.go",
            "main.py",
        ],
    )
    def test_interface_paths_match(self, path):
        assert rw.TM_SURFACE_RX.search(path)

    @pytest.mark.parametrize(
        "path",
        [
            "docs/README.md",
            "pkg/util/strings.go",
            "test/e2e/suite_test.go",
            "pkg/apimachinery_helper.go",
            "internal/database/pool.go",
            "hack/build.sh",
        ],
    )
    def test_non_interface_paths_do_not_match(self, path):
        """The cadence doc records that a broad matcher hit 90% of
        changed repos and was useless — this one stays directory-
        anchored."""
        assert not rw.TM_SURFACE_RX.search(path)

    def test_change_metrics_counts_surface_files(self):
        m = rw.change_metrics(
            [
                {"filename": "pkg/api/v1/types.go", "changes": 10},
                {"filename": "pkg/util/x.go", "changes": 5},
                {"filename": "vendor/z/api/y.go", "changes": 99},
            ]
        )
        assert m["tm_files"] == 1  # vendor/ is not first-party


class TestThreatModelPrStamp:
    def _rows(self):
        return [
            {"repo_key": "a", "lane": "diff-scan"},
            {"repo_key": "b", "lane": "diff-scan-quarterly"},
            {"repo_key": "c", "lane": "full-audit"},
            {"repo_key": "d", "lane": "diff-scan"},
        ]

    def test_stamps_sensitive_and_surface_rows_only(self):
        rows = self._rows()
        by_key = {
            "a": {"S": True, "tm_files": 0, "tm_path": "/m/a.md"},
            "b": {"S": False, "tm_files": 3, "tm_path": "/m/b.md"},
            "c": {"S": True, "tm_files": 5, "tm_path": "/m/c.md"},
            "d": {"S": False, "tm_files": 0, "tm_path": "/m/d.md"},
        }
        stats = rw.stamp_threat_model_pr(rows, by_key)
        assert stats == {"eligible": 3, "stamped": 2, "no_model": 0}
        assert rows[0]["threat_model_pr"]["mode"] == "report-only"
        assert "sensitive-identifier" in rows[0]["threat_model_pr"]["reason"]
        assert "interface-bearing" in rows[1]["threat_model_pr"]["reason"]
        # a full-audit row already re-reads the whole repo
        assert "threat_model_pr" not in rows[2]
        # an unremarkable diff is not a surface change
        assert "threat_model_pr" not in rows[3]

    def test_no_model_is_counted_not_stamped(self):
        rows = [{"repo_key": "a", "lane": "diff-scan"}]
        stats = rw.stamp_threat_model_pr(rows, {"a": {"S": True, "tm_files": 1, "tm_path": None}})
        assert stats["no_model"] == 1 and stats["stamped"] == 0
        assert "threat_model_pr" not in rows[0]


class TestThreatModelQuarterlyRows:
    def _entries(self):
        return [
            {
                "repo_key": "a",
                "repo_url": "u/a",
                "tm_path": "/m/a.md",
                "tm_age_days": 140,
                "exposure": "public-external",
            },
            {
                "repo_key": "b",
                "repo_url": "u/b",
                "tm_path": "/m/b.md",
                "tm_age_days": 30,
                "exposure": "public-external",
            },
            {
                "repo_key": "c",
                "repo_url": "u/c",
                "tm_path": None,
                "tm_age_days": None,
                "exposure": "public-external",
            },
        ]

    def test_only_models_past_the_threshold(self):
        rows = rw.threat_model_quarterly_rows(self._entries(), set(), 92)
        assert [r["repo_key"] for r in rows] == ["a"]
        assert rows[0]["lane"] == "threat-model-quarterly"
        assert rows[0]["rule"] == "threat-model-3"
        assert rows[0]["threat_model_age_days"] == 140

    def test_release_reviewed_repos_are_excluded(self):
        """Phase 3 is the backstop for repos Phases 1-2 did NOT cover —
        it must not double-book a repo already being reviewed."""
        rows = rw.threat_model_quarterly_rows(self._entries(), {"u/a"}, 92)
        assert rows == []

    def test_threshold_is_a_parameter(self):
        rows = rw.threat_model_quarterly_rows(self._entries(), set(), 20)
        assert {r["repo_key"] for r in rows} == {"a", "b"}


class TestThreatModelLanesRegistered:
    def test_new_lanes_are_in_the_ordered_tuple(self):
        """LANES.index is the primary sort key — a lane missing here
        raises ValueError at sort time, not at emit time."""
        assert "threat-model-review" in rw.LANES
        assert "threat-model-quarterly" in rw.LANES

    def test_quarterly_sorts_after_the_diff_pool_but_before_none(self):
        assert (
            rw.LANES.index("diff-scan-quarterly")
            < rw.LANES.index("threat-model-quarterly")
            < rw.LANES.index("none")
        )

    def test_remodel_changes_are_major_minor_only(self):
        assert rw.RELEASE_REMODEL_CHANGES == ("major", "minor")


# ---------------------------------------------------------------------------
# budget-policy reader (fixed 2026-08-05 — silently read the wrong key)
# ---------------------------------------------------------------------------


def _policy(tmp_path, body: str) -> Path:
    p = tmp_path / "budget-policy.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


class TestReadPolicyBudget:
    def test_enforcement_none_does_not_gate(self, tmp_path):
        """The shipped posture. A policy that documents its own
        non-enforcement must not silently become a control."""
        p = _policy(
            tmp_path,
            """
            budget_policy:
              enforcement: none
              monthly_budget: {usd_central: 23000}
        """,
        )
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling is None
        assert "enforcement=none" in why

    def test_advisory_reads_the_nested_key(self, tmp_path):
        """The actual bug: the reader looked for a flat `monthly_usd`,
        the policy nests it under monthly_budget.usd_central, so it
        found nothing on every run and reported budget_usd: null."""
        p = _policy(
            tmp_path,
            """
            budget_policy:
              enforcement: advisory
              monthly_budget: {usd_central: 23000, usd_band_low: 19000}
        """,
        )
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling == 23000.0
        assert "monthly_budget.usd_central" in why

    def test_legacy_flat_key_still_read_and_named_honestly(self, tmp_path):
        p = _policy(
            tmp_path,
            """
            budget_policy:
              enforcement: advisory
              monthly_usd: 9000
        """,
        )
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling == 9000.0
        assert "legacy flat key" in why

    def test_gating_asked_but_no_figure_is_loud_not_silent(self, tmp_path):
        """The original failure SHAPE: asked to gate, found no number.
        Must be reported, never degrade to 'no budget configured'."""
        p = _policy(
            tmp_path,
            """
            budget_policy:
              enforcement: advisory
              per_run_defaults: {default: 100}
        """,
        )
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling is None
        assert "MISSING" in why

    def test_enforced_is_platform_only_but_still_applied(self, tmp_path):
        p = _policy(
            tmp_path,
            """
            budget_policy:
              enforcement: enforced
              monthly_budget: {usd_central: 12000}
        """,
        )
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling == 12000.0
        assert "platform-only" in why

    def test_unrecognized_enforcement_degrades_to_none(self, tmp_path):
        p = _policy(
            tmp_path,
            """
            budget_policy:
              enforcement: totally-on
              monthly_budget: {usd_central: 23000}
        """,
        )
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling is None
        assert "not a recognized mode" in why

    def test_zero_and_boolean_are_not_ceilings(self, tmp_path):
        for val in ("0", "true"):
            p = _policy(
                tmp_path,
                f"""
                budget_policy:
                  enforcement: advisory
                  monthly_budget: {{usd_central: {val}}}
            """,
            )
            ceiling, why = rw.read_policy_budget(p)
            assert ceiling is None, val
            assert "MISSING" in why

    def test_missing_file_explains_itself(self, tmp_path):
        ceiling, why = rw.read_policy_budget(tmp_path / "absent.yaml")
        assert ceiling is None and "budget-policy.yaml" in why

    def test_unparseable_file_never_raises(self, tmp_path):
        p = tmp_path / "budget-policy.yaml"
        p.write_text("budget_policy: [oops\n", encoding="utf-8")
        ceiling, why = rw.read_policy_budget(p)
        assert ceiling is None and "unparseable" in why

    def test_every_path_returns_a_reason(self, tmp_path):
        """`budget_usd: null` with no explanation is what let the bug
        hide for months — no branch may return an empty reason."""
        p = _policy(tmp_path, "budget_policy:\n  enforcement: none\n")
        for target in (p, tmp_path / "absent.yaml"):
            _, why = rw.read_policy_budget(target)
            assert why and isinstance(why, str)


from traust.paths import optional_config_path as _cfg_path


class TestShippedPolicyPosture:
    def test_live_policy_does_not_gate_the_router(self):
        """Regression guard on the REAL config: budget-policy.yaml ships
        enforcement: none (L1 advisory is Phase 3 of the budget-policy
        plan). Measured 2026-08-05 the live worklist projected just under
        the configured ceiling — so flipping this on
        by accident would start dropping full audits within one ordinary
        run. If this test fails, that activation was deliberate: confirm
        it, don't just update the assertion."""
        live = _cfg_path("budget-policy.yaml")
        if not live.is_file():
            pytest.skip("no deployment budget-policy.yaml in this checkout")
        ceiling, why = rw.read_policy_budget(live)
        # Assert the PROPERTY (no binding ceiling), not the mode string:
        # the shipped posture moved none -> observe on 2026-08-06 and
        # observe is also non-gating by construction. What must never
        # change silently is that the drop path sees no ceiling.
        assert ceiling is None, why
        assert any(m in why for m in ("enforcement=none", "enforcement=observe")), why

    def test_the_figure_is_readable_once_enforcement_flips(self, tmp_path):
        """The other half: the live policy's shape must actually parse,
        so flipping enforcement produces a ceiling rather than the
        'MISSING' warning."""
        live = _cfg_path("budget-policy.yaml")
        if not live.is_file():
            pytest.skip("no deployment budget-policy.yaml in this checkout")
        text = live.read_text(encoding="utf-8")
        for mode in ("enforcement: none", "enforcement: observe"):
            if mode in text:
                text = text.replace(mode, "enforcement: advisory", 1)
                break
        p = tmp_path / "budget-policy.yaml"
        p.write_text(text, encoding="utf-8")
        ceiling, why = rw.read_policy_budget(p)
        # the shipped/fixture budget-policy.example posture figure
        assert ceiling == 10000.0, why

    def test_shipped_observe_ceiling_is_visible_only_to_the_shadow(self):
        """Phase 1's safety property, asserted against the REAL config:
        the drop path sees nothing, the shadow reader sees the figure."""
        live = _cfg_path("budget-policy.yaml")
        if not live.is_file():
            pytest.skip("no deployment budget-policy.yaml in this checkout")
        assert rw.read_policy_budget(live)[0] is None
        shadow, _ = rw.read_policy_shadow_ceiling(live)
        assert shadow is None or shadow > 0
