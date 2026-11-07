#!/usr/bin/env python3
"""
Comprehensive test suite for the validate-findings harness.

Covers:
  - ingest.py: report discovery, JSON/MD parsing, PoC extraction, scope inference
  - plan.py: replay/adapted/chained/novel step generation
  - chain.py: capability vocabulary, graph construction, kill-chain DFS
  - novel.py: recon steps, diff_surfaces, probe materialization
  - execute.py: plan loading, scope gating, precondition checking, two-pass novel
  - report.py: JSON assembly, verdict rollup, Markdown rendering
  - adapters: verdict logic for k8s, container, wasm
"""

import base64
import json
import textwrap
import threading

import pytest
from adapters import StepResult, get_adapter, new_adapter
from adapters.container import ContainerAdapter
from adapters.k8s import K8sAdapter
from adapters.wasm import WasmAdapter
from chain import (
    Chain,
    Node,
    _close,
    _finding_caps,
    _match_caps,
    build_graph,
    find_chains,
)
from execute import AuditLog, _step_action, run

# --- imports ----------------------------------------------------------
from ingest import (
    Finding,
    Normalized,
    PoC,
    ThreatModel,
    _extract_pocs,
    _harvest_scope_hints,
    _is_plausible_ns,
    _md_tables,
    discover_package,
    discover_reports,
    ingest,
    is_package,
    resolve_source,
)
from novel import (
    _adapter_for,
    _target_for,
    diff_surfaces,
    probe_steps,
    recon_steps,
)
from plan import (
    _adapted_step,
    _http_adapted_step,
    _step_from_poc,
    build_plan,
    summarize,
    write_plan,
)
from report import (
    _strip_nones,
    build_validation_json,
    harness_version,
    render_markdown,
    write,
)
from scope import ClusterScope, Scope
from traust_core.v1.models.validation import HttpDiscovery, HttpTarget

# ======================================================================
# INGEST
# ======================================================================


# A base64-wrapped JWT-shaped header (what a leaked Secret carrying a token
# looks like), built at runtime so no token-shaped literal sits in the tree.
_B64_WRAPPED_JWT_HEADER = base64.b64encode(
    base64.b64encode(json.dumps({"alg": "RS256", "kid": "test-key"}).encode())
).decode()


class TestExtractPocs:
    def test_fenced_yaml(self):
        text = "text\n```yaml\napiVersion: v1\nkind: Pod\n```\nmore"
        pocs = _extract_pocs(text, "body")
        assert len(pocs) == 1
        assert pocs[0].lang == "yaml"
        assert "apiVersion" in pocs[0].body

    def test_fenced_bash(self):
        text = "```bash\nkubectl get pods\n```"
        pocs = _extract_pocs(text, "evidence")
        assert pocs[0].lang == "bash"

    def test_empty_fence_skipped(self):
        text = "```yaml\n\n```"
        assert _extract_pocs(text, "x") == []

    def test_no_fences(self):
        assert _extract_pocs("no fences here", "x") == []

    def test_none_input(self):
        assert _extract_pocs(None, "x") == []


class TestMdTables:
    def test_basic_table(self):
        text = "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |"
        tables = _md_tables(text)
        assert len(tables) == 1
        assert tables[0] == [["A", "B"], ["1", "2"], ["3", "4"]]

    def test_multiple_tables(self):
        text = "| X |\n|---|\n| 1 |\n\ntext\n\n| Y |\n|---|\n| 2 |"
        tables = _md_tables(text)
        assert len(tables) == 2


class TestNsHintFilter:
    def test_plausible_openshift_ns(self):
        assert _is_plausible_ns("openshift-dr-hub") is True

    def test_plausible_ramen_ns(self):
        assert _is_plausible_ns("ramen-ops") is True

    def test_rejects_prose_compound(self):
        assert _is_plausible_ns("production-database") is False

    def test_rejects_denylist(self):
        assert _is_plausible_ns("cross-namespace") is False

    def test_rejects_my_application(self):
        assert _is_plausible_ns("my-application") is False

    def test_accepts_real_ns(self):
        assert _is_plausible_ns("cert-manager") is True

    def test_accepts_metallb(self):
        assert _is_plausible_ns("metallb-system") is True


class TestHarvestScopeHints:
    def test_extracts_real_ns(self):
        n = Normalized(target_name="t", source_dir="/tmp")
        _harvest_scope_hints("namespace: ramen-ops some text", n)
        assert "ramen-ops" in n.inferred_scope["clusters"].get("__current__", [])

    def test_filters_prose_ns(self):
        n = Normalized(target_name="t", source_dir="/tmp")
        _harvest_scope_hints("namespace: production-database is a thing", n)
        assert n.inferred_scope["clusters"].get("__current__", []) == []

    def test_extracts_images(self):
        n = Normalized(target_name="t", source_dir="/tmp")
        _harvest_scope_hints("uses quay.io/ramendr/ramen-operator:v4.18", n)
        assert any("quay.io/ramendr" in img for img in n.inferred_scope["images"])

    def test_deduplicates(self):
        n = Normalized(target_name="t", source_dir="/tmp")
        _harvest_scope_hints("namespace: ramen-ops\nnamespace: ramen-ops", n)
        assert n.inferred_scope["clusters"]["__current__"].count("ramen-ops") == 1


class TestResolveSource:
    def test_directory(self, tmp_path):
        assert resolve_source(str(tmp_path)) == tmp_path.resolve()

    def test_file(self, tmp_path):
        f = tmp_path / "report.json"
        f.write_text("{}")
        assert resolve_source(str(f)) == tmp_path.resolve()

    def test_nonexistent(self):
        with pytest.raises(FileNotFoundError):
            resolve_source("/nonexistent/path/that/does/not/exist")


class TestDiscoverReports:
    def test_finds_json_over_md(self, tmp_path):
        (tmp_path / "foo-security-audit.json").write_text("{}")
        (tmp_path / "foo-security-audit.md").write_text("# report")
        found = discover_reports(tmp_path)
        assert found["security-audit"].suffix == ".json"

    def test_finds_md_fallback(self, tmp_path):
        (tmp_path / "bar-security-audit.md").write_text("# report")
        found = discover_reports(tmp_path)
        assert found["security-audit"].suffix == ".md"

    def test_finds_triage(self, tmp_path):
        (tmp_path / "x-triage.json").write_text("{}")
        found = discover_reports(tmp_path)
        assert "triage" in found

    def test_empty_dir(self, tmp_path):
        assert discover_reports(tmp_path) == {}


class TestIngestJsonReport:
    @pytest.fixture
    def audit_dir(self, tmp_path):
        audit = {
            "title": "Security Audit",
            "findings": [
                {
                    "id": "FIND-001",
                    "title": "RBAC over-grant",
                    "severity": "high",
                    "cwes": ["CWE-269"],
                    "locations": [{"path": "deploy/rbac.yaml", "line": 10}],
                    "description": "ClusterRole grants `* * *`.\n```yaml\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n```",
                    "attack_pattern": "kubectl auth can-i --list",
                    "evidence": [{"code": "rules:\n- apiGroups: ['*']", "language": "yaml"}],
                },
                {
                    "id": "FIND-002",
                    "title": "SSRF via URL field",
                    "severity": "medium",
                    "cwes": ["CWE-918"],
                    "locations": [{"path": "api/handler.go", "line": 42}],
                    "description": "Operator fetches user-controlled URL in namespace: ramen-ops",
                },
            ],
        }
        (tmp_path / "test-security-audit.json").write_text(json.dumps(audit))
        return tmp_path

    def test_ingest_parses_findings(self, audit_dir):
        n = ingest(str(audit_dir))
        assert len(n.findings) == 2
        assert n.findings[0].id == "FIND-001"
        assert n.findings[0].severity == "high"
        assert "CWE-269" in n.findings[0].cwes

    def test_ingest_extracts_pocs(self, audit_dir):
        n = ingest(str(audit_dir))
        # FIND-001 should have PoCs from evidence + description
        pocs = n.findings[0].pocs
        assert len(pocs) >= 1

    def test_ingest_infers_scope(self, audit_dir):
        n = ingest(str(audit_dir))
        ns_list = n.inferred_scope["clusters"].get("__current__", [])
        assert "ramen-ops" in ns_list

    def test_ingest_source_reports(self, audit_dir):
        n = ingest(str(audit_dir))
        assert len(n.source_reports) == 1
        assert n.source_reports[0]["kind"] == "security-audit"
        assert n.source_reports[0]["sha256"]  # not empty


class TestIngestMdReport:
    @pytest.fixture
    def md_dir(self, tmp_path):
        md = textwrap.dedent("""\
        # Security Audit

        ## FIND-001 — **CRITICAL** — RBAC over-grant

        CWE-269 cluster-admin equivalent.

        ```yaml
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        ```

        ## FIND-002 — **MEDIUM** — Missing rate limits

        CWE-770 no throttling.
        """)
        (tmp_path / "test-security-audit.md").write_text(md)
        return tmp_path

    def test_md_parse_headings(self, md_dir):
        n = ingest(str(md_dir))
        assert len(n.findings) == 2
        assert n.findings[0].id == "FIND-001"
        assert n.findings[0].severity == "critical"

    def test_md_extracts_cwes(self, md_dir):
        n = ingest(str(md_dir))
        assert "CWE-269" in n.findings[0].cwes


class TestIngestTriage:
    def test_triage_enrichment(self, tmp_path):
        audit = {
            "findings": [
                {
                    "id": "F1",
                    "title": "Test",
                    "severity": "high",
                    "cwes": [],
                    "locations": [{"path": "x.go"}],
                    "description": "desc",
                }
            ]
        }
        triage = {
            "findings": [
                {
                    "id": "TF1",
                    "source": "audit.json#F1",
                    "verdict": "true_positive",
                    "verify_verdict": "exploitable",
                    "confidence": 0.95,
                    "preconditions": ["network access"],
                    "owner_hint": "team-a",
                }
            ]
        }
        (tmp_path / "x-security-audit.json").write_text(json.dumps(audit))
        (tmp_path / "x-triage.json").write_text(json.dumps(triage))
        n = ingest(str(tmp_path))
        f = n.findings[0]
        assert f.triage_verdict == "true_positive"
        assert f.confidence == 0.95
        assert f.owner_hint == "team-a"


class TestIngestThreatModel:
    def test_threat_model_tables(self, tmp_path):
        md = textwrap.dedent("""\
        # Threat Model

        ## Assets

        | Asset | Description | Sensitivity |
        |---|---|---|
        | SA Token | ServiceAccount bearer token | critical |
        | Config | Operator config | medium |

        ## Entry Points

        | Entry Point | Description | Trust Boundary | Reachable Assets |
        |---|---|---|---|
        | CRD API | Tenant CR submission | authenticated | SA Token, Config |

        ## Threats

        | ID | Threat | Actor | Surface | Asset | Impact | Likelihood | Status | Controls | Evidence |
        |---|---|---|---|---|---|---|---|---|---|
        | T-001 | Token theft | tenant | CRD API | SA Token | critical | high | unmitigated | none | F1 |
        """)
        audit = {
            "findings": [
                {
                    "id": "F1",
                    "title": "Token leak",
                    "severity": "high",
                    "cwes": ["CWE-522"],
                    "locations": [{"path": "x.go"}],
                    "description": "d",
                }
            ]
        }
        (tmp_path / "x-security-audit.json").write_text(json.dumps(audit))
        (tmp_path / "x-threat-model.md").write_text(md)
        n = ingest(str(tmp_path))
        assert len(n.threat_model.assets) == 2
        assert len(n.threat_model.entry_points) == 1
        assert len(n.threat_model.threats) == 1
        assert "T-001" in n.findings[0].threat_ids


# ======================================================================
# PRODUCT PACKAGE (processed-results) SUPPORT
# ======================================================================


def _make_audit_json(findings_data: list[dict]) -> str:
    """Helper to build a minimal valid security-audit JSON string."""
    return json.dumps({"findings": findings_data})


class TestIsPackage:
    def test_single_repo_dir_is_not_package(self, tmp_path):
        (tmp_path / "x-security-audit.md").write_text("# audit")
        assert is_package(tmp_path) is False

    def test_package_with_flat_repos(self, tmp_path):
        r1 = tmp_path / "repo-a"
        r1.mkdir()
        (r1 / "repo-a-security-audit.md").write_text("# audit")
        r2 = tmp_path / "repo-b"
        r2.mkdir()
        (r2 / "repo-b-security-audit.json").write_text(
            _make_audit_json(
                [
                    {
                        "id": "F1",
                        "title": "T",
                        "severity": "low",
                        "cwes": [],
                        "locations": [{"path": "x"}],
                        "description": "d" * 50,
                    }
                ]
            )
        )
        assert is_package(tmp_path) is True

    def test_package_with_nested_groups(self, tmp_path):
        group = tmp_path / "SubGroup"
        group.mkdir()
        repo = group / "repo-c"
        repo.mkdir()
        (repo / "repo-c-security-audit.md").write_text("# audit")
        assert is_package(tmp_path) is True

    def test_empty_dir_is_not_package(self, tmp_path):
        assert is_package(tmp_path) is False

    def test_dir_with_only_html_readme_is_not_package(self, tmp_path):
        (tmp_path / "README.md").write_text("# readme")
        (tmp_path / "Executive-Summary.html").write_text("<html></html>")
        assert is_package(tmp_path) is False


class TestDiscoverPackage:
    def test_flat_repos(self, tmp_path):
        for name in ("repo-a", "repo-b"):
            d = tmp_path / name
            d.mkdir()
            (d / f"{name}-security-audit.md").write_text("# audit")
        dirs = discover_package(tmp_path)
        assert len(dirs) == 2
        assert {d.name for d in dirs} == {"repo-a", "repo-b"}

    def test_nested_groups(self, tmp_path):
        for group, repos in [("ACM", ["console", "rbac"]), ("MCE", ["agent"])]:
            g = tmp_path / group
            g.mkdir()
            for r in repos:
                rd = g / r
                rd.mkdir()
                (rd / f"{r}-security-audit.md").write_text("# audit")
        dirs = discover_package(tmp_path)
        assert len(dirs) == 3
        names = {d.name for d in dirs}
        assert "console" in names
        assert "agent" in names

    def test_mixed_flat_and_nested(self, tmp_path):
        # flat repo
        r1 = tmp_path / "repo-flat"
        r1.mkdir()
        (r1 / "repo-flat-security-audit.md").write_text("# audit")
        # nested repo
        g = tmp_path / "SubGroup"
        g.mkdir()
        r2 = g / "repo-nested"
        r2.mkdir()
        (r2 / "repo-nested-security-audit.md").write_text("# audit")
        dirs = discover_package(tmp_path)
        assert len(dirs) == 2

    def test_skips_dotdirs(self, tmp_path):
        hidden = tmp_path / ".git"
        hidden.mkdir()
        (hidden / "x-security-audit.md").write_text("# audit")
        assert discover_package(tmp_path) == []

    def test_skips_dirs_without_reports(self, tmp_path):
        d = tmp_path / "docs"
        d.mkdir()
        (d / "README.md").write_text("# docs")
        assert discover_package(tmp_path) == []


class TestResolveSourceProcessedResults:
    def test_slug_with_suffix(self, tmp_path):
        pkg = tmp_path / "my-product-findings"
        repo = pkg / "repo-a"
        repo.mkdir(parents=True)
        (repo / "repo-a-security-audit.md").write_text("# audit")
        result = resolve_source("my-product-findings", processed_root=tmp_path)
        assert result == pkg.resolve()

    def test_bare_slug(self, tmp_path):
        pkg = tmp_path / "my-product-findings"
        repo = pkg / "repo-a"
        repo.mkdir(parents=True)
        (repo / "repo-a-security-audit.md").write_text("# audit")
        result = resolve_source("my-product", processed_root=tmp_path)
        assert result == pkg.resolve()


class TestIngestPackage:
    @pytest.fixture
    def package_dir(self, tmp_path):
        """Build a synthetic product package with 2 repos."""
        pkg = tmp_path / "test-product-findings"
        for name, findings in [
            (
                "svc-alpha",
                [
                    {
                        "id": "A-001",
                        "title": "Alpha RBAC over-grant",
                        "severity": "high",
                        "cwes": ["CWE-269"],
                        "locations": [{"path": "rbac.yaml"}],
                        "description": "d" * 50,
                    },
                ],
            ),
            (
                "svc-beta",
                [
                    {
                        "id": "B-001",
                        "title": "Beta SSRF",
                        "severity": "medium",
                        "cwes": ["CWE-918"],
                        "locations": [{"path": "handler.go"}],
                        "description": "d" * 50,
                    },
                    {
                        "id": "B-002",
                        "title": "Beta path traversal",
                        "severity": "high",
                        "cwes": ["CWE-22"],
                        "locations": [{"path": "upload.go"}],
                        "description": "d" * 50,
                    },
                ],
            ),
        ]:
            d = pkg / name
            d.mkdir(parents=True)
            (d / f"{name}-security-audit.json").write_text(_make_audit_json(findings))
        # Add an executive summary and README at the top (should be ignored)
        (pkg / "Executive-Summary-Test.html").write_text("<html></html>")
        (pkg / "README.md").write_text("# Test Product Findings")
        return pkg

    def test_ingests_all_repos(self, package_dir):
        n = ingest(str(package_dir))
        assert len(n.findings) == 3
        ids = {f.id for f in n.findings}
        assert ids == {"svc-alpha/A-001", "svc-beta/B-001", "svc-beta/B-002"}

    def test_findings_tagged_with_source_repo(self, package_dir):
        n = ingest(str(package_dir))
        repos = {f.source_repo for f in n.findings}
        assert repos == {"svc-alpha", "svc-beta"}

    def test_source_reports_from_all_repos(self, package_dir):
        n = ingest(str(package_dir))
        sa_reports = [r for r in n.source_reports if r["kind"] == "security-audit"]
        assert len(sa_reports) == 2

    def test_target_name_is_package_slug(self, package_dir):
        n = ingest(str(package_dir))
        assert n.target_name == "test-product-findings"

    def test_nested_group_labels(self, tmp_path):
        """Two-level nesting: SubGroup/repo → source_repo = 'SubGroup/repo'."""
        pkg = tmp_path / "nested-findings"
        group = pkg / "CoreTeam"
        rd = group / "controller"
        rd.mkdir(parents=True)
        (rd / "controller-security-audit.json").write_text(
            _make_audit_json(
                [
                    {
                        "id": "N-001",
                        "title": "Nested finding",
                        "severity": "low",
                        "cwes": ["CWE-200"],
                        "locations": [{"path": "x.go"}],
                        "description": "d" * 50,
                    },
                ]
            )
        )
        n = ingest(str(pkg))
        assert n.findings[0].source_repo == "CoreTeam/controller"

    def test_empty_package_raises(self, tmp_path):
        pkg = tmp_path / "empty-findings"
        pkg.mkdir()
        (pkg / "README.md").write_text("# empty")
        with pytest.raises(FileNotFoundError):
            ingest(str(pkg))

    def test_package_with_empty_subdirs_raises(self, tmp_path):
        """A dir that looks like a package (no top-level reports, has subdirs)
        but whose subdirs contain no audit reports should raise."""
        pkg = tmp_path / "hollow-findings"
        (pkg / "some-dir").mkdir(parents=True)
        (pkg / "some-dir" / "README.md").write_text("# just docs")
        # is_package returns False because no sub-dir has audit reports,
        # so it falls through to the single-repo path and raises.
        with pytest.raises(FileNotFoundError):
            ingest(str(pkg))


class TestIngestPackageWithTriageAndThreatModel:
    def test_triage_enrichment_across_repos(self, tmp_path):
        """Triage in one repo correctly enriches findings from that repo."""
        pkg = tmp_path / "multi-findings"
        repo = pkg / "svc"
        repo.mkdir(parents=True)
        audit = {
            "findings": [
                {
                    "id": "F1",
                    "title": "Vuln",
                    "severity": "high",
                    "cwes": ["CWE-269"],
                    "locations": [{"path": "x.go"}],
                    "description": "d" * 50,
                },
            ]
        }
        triage = {
            "findings": [
                {
                    "id": "TF1",
                    "source": "audit.json#F1",
                    "verdict": "true_positive",
                    "confidence": 0.9,
                },
            ]
        }
        (repo / "svc-security-audit.json").write_text(json.dumps(audit))
        (repo / "svc-triage.json").write_text(json.dumps(triage))
        n = ingest(str(pkg))
        assert n.findings[0].triage_verdict == "true_positive"
        assert n.findings[0].source_repo == "svc"
        assert n.findings[0].id == "svc/F1"

    def test_triage_isolation_between_repos(self, tmp_path):
        """Triage from repo A must NOT bleed into repo B's findings."""
        pkg = tmp_path / "iso-findings"
        # Repo A: has finding F1 with triage
        repo_a = pkg / "repo-a"
        repo_a.mkdir(parents=True)
        (repo_a / "repo-a-security-audit.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "FIND-001",
                            "title": "A-vuln",
                            "severity": "high",
                            "cwes": ["CWE-269"],
                            "locations": [{"path": "a.go"}],
                            "description": "d" * 50,
                        }
                    ]
                }
            )
        )
        (repo_a / "repo-a-triage.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "TA1",
                            "source": "#FIND-001",
                            "verdict": "true_positive",
                            "confidence": 0.95,
                        }
                    ]
                }
            )
        )
        # Repo B: has finding FIND-001 (same local ID!) with different triage
        repo_b = pkg / "repo-b"
        repo_b.mkdir(parents=True)
        (repo_b / "repo-b-security-audit.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "FIND-001",
                            "title": "B-vuln",
                            "severity": "low",
                            "cwes": ["CWE-200"],
                            "locations": [{"path": "b.go"}],
                            "description": "d" * 50,
                        }
                    ]
                }
            )
        )
        (repo_b / "repo-b-triage.json").write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "TB1",
                            "source": "#FIND-001",
                            "verdict": "false_positive",
                            "confidence": 0.8,
                        }
                    ]
                }
            )
        )
        n = ingest(str(pkg))
        by_id = {f.id: f for f in n.findings}
        # Each finding gets its own repo's triage, not the other's
        assert by_id["repo-a/FIND-001"].triage_verdict == "true_positive"
        assert by_id["repo-a/FIND-001"].confidence == 0.95
        assert by_id["repo-b/FIND-001"].triage_verdict == "false_positive"
        assert by_id["repo-b/FIND-001"].confidence == 0.8

    def test_no_id_collisions(self, tmp_path):
        """Two repos with identical local finding IDs get unique global IDs."""
        pkg = tmp_path / "dup-findings"
        for name in ("x", "y"):
            d = pkg / name
            d.mkdir(parents=True)
            (d / f"{name}-security-audit.json").write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "FIND-001",
                                "title": f"{name} vuln",
                                "severity": "high",
                                "cwes": ["CWE-269"],
                                "locations": [{"path": f"{name}.go"}],
                                "description": "d" * 50,
                            }
                        ]
                    }
                )
            )
        n = ingest(str(pkg))
        ids = [f.id for f in n.findings]
        assert len(ids) == len(set(ids)), f"ID collision: {ids}"
        assert "x/FIND-001" in ids
        assert "y/FIND-001" in ids


# ======================================================================
# CHAIN
# ======================================================================


class TestCapabilities:
    def test_match_caps_sa_token(self):
        assert "sa-token" in _match_caps("service account token stolen")

    def test_match_caps_cluster_admin(self):
        assert "cluster-admin" in _match_caps("grants cluster-admin")

    def test_match_caps_ssrf(self):
        assert "ssrf" in _match_caps("SSRF to metadata service")

    def test_close_cluster_admin(self):
        closed = _close({"cluster-admin"})
        assert "rbac-escalation" in closed
        assert "ns-escape" in closed
        assert "pod-exec" in closed
        assert "sa-token" in closed

    def test_close_host_exec(self):
        closed = _close({"host-exec"})
        assert "file-read" in closed
        assert "container-exec" in closed

    def test_close_empty(self):
        assert _close(set()) == set()


class TestFindingCaps:
    def test_finding_yields_from_cwes(self):
        f = Finding(id="F1", title="RBAC escalation", severity="high", cwes=["CWE-269"])
        _, yields = _finding_caps(f)
        assert "rbac-escalation" in yields

    def test_finding_yields_from_text(self):
        f = Finding(
            id="F1",
            title="Steals SA token",
            severity="high",
            description="extracts service account token and uses it",
        )
        _, yields = _finding_caps(f)
        assert "sa-token" in yields

    def test_finding_requires_from_preconditions(self):
        f = Finding(
            id="F1",
            title="test",
            severity="high",
            preconditions=["requires pods/exec in target namespace"],
        )
        req, _ = _finding_caps(f)
        assert "pod-exec" in req


class TestBuildGraph:
    def test_entry_to_finding_edge(self):
        findings = [Finding(id="F1", title="test", severity="high", cwes=["CWE-269"])]
        tm = ThreatModel(
            entry_points=[
                {"name": "API", "trust_boundary": "unauthenticated", "reachable_assets": []}
            ],
            assets=[],
            threats=[],
        )
        _nodes, edges, _meta = build_graph(findings, tm)
        entry = Node("entry", "API")
        fn = Node("finding", "F1")
        assert fn in edges.get(entry, set())

    def test_finding_to_finding_edge(self):
        f1 = Finding(
            id="F1",
            title="Token theft",
            severity="high",
            cwes=["CWE-522"],
            description="steals SA token",
        )
        f2 = Finding(
            id="F2",
            title="Escalation",
            severity="critical",
            preconditions=["requires sa-token"],
            cwes=["CWE-269"],
        )
        tm = ThreatModel()
        _nodes, edges, _meta = build_graph([f1, f2], tm)
        n1 = Node("finding", "F1")
        n2 = Node("finding", "F2")
        assert n2 in edges.get(n1, set())


class TestFindChains:
    def test_simple_chain(self):
        f1 = Finding(
            id="F1",
            title="Token theft",
            severity="high",
            cwes=["CWE-522"],
            description="steals service account token",
        )
        f2 = Finding(
            id="F2",
            title="Cluster admin via token",
            severity="critical",
            cwes=["CWE-269"],
            preconditions=["requires sa-token"],
            description="escalates to full admin access via stolen token",
        )
        tm = ThreatModel(
            entry_points=[
                {
                    "name": "CRD API",
                    "trust_boundary": "authenticated",
                    "reachable_assets": ["Admin Access"],
                }
            ],
            assets=[
                {
                    "name": "Admin Access",
                    "sensitivity": "critical",
                    "description": "Full cluster-admin access",
                }
            ],
            threats=[],
        )
        chains = find_chains([f1, f2], tm)
        # entry→F1 (no preconditions); F1→F2 (yields sa-token satisfies F2's
        # precondition); F2→Admin Access (description mentions "admin access")
        assert len(chains) >= 1
        c = chains[0]
        assert "F1" in c.finding_ids or "F2" in c.finding_ids
        assert c.mitre  # has MITRE refs

    def test_no_chains_without_entry(self):
        f1 = Finding(
            id="F1",
            title="test",
            severity="low",
            cwes=["CWE-200"],
            preconditions=["requires cluster-admin"],
        )
        tm = ThreatModel()
        chains = find_chains([f1], tm)
        # unauthenticated fallback entry should not satisfy cluster-admin precondition
        assert len(chains) == 0

    def test_false_positive_excluded(self):
        f1 = Finding(
            id="F1", title="FP", severity="high", cwes=["CWE-269"], triage_verdict="false_positive"
        )
        tm = ThreatModel(
            entry_points=[
                {"name": "API", "trust_boundary": "unauthenticated", "reachable_assets": []}
            ],
        )
        nodes, _edges, _meta = build_graph([f1], tm)
        assert Node("finding", "F1") not in nodes


# ======================================================================
# NOVEL
# ======================================================================


class TestReconSteps:
    def test_k8s_recon(self):
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app-ns"])
        steps = recon_steps(scope)
        assert len(steps) >= 4
        assert all(s.classification == "safe" for s in steps)
        assert any("crd" in s.cmd for s in steps)

    def test_container_recon(self):
        scope = Scope()
        scope.containers = ["my-container"]
        scope.container_runtimes = ["podman"]
        steps = recon_steps(scope)
        assert any(s.adapter == "container" for s in steps)

    def test_wasm_recon(self):
        scope = Scope()
        scope.wasm_artifacts = ["policy.wasm"]
        steps = recon_steps(scope)
        assert any(s.adapter == "wasm" for s in steps)


class TestDiffSurfaces:
    def test_crd_cross_ns(self):
        inv = {
            "crds": [
                {"api": "v1", "kind": "MyResource", "ref_fields": ["secretRef"], "url_fields": []}
            ],
            "rbac": [],
            "pods": [],
            "containers": [],
            "components": [],
            "wasm": [],
        }
        tm = ThreatModel()
        cands = diff_surfaces(inv, tm)
        assert any(sc == "crd-cross-ns-ref" for _, sc, _ in cands)

    def test_pod_hostpath(self):
        inv = {
            "crds": [],
            "rbac": [],
            "pods": [
                {
                    "ns": "app",
                    "name": "pod-1",
                    "caps": [],
                    "hostpath": ["/var/log"],
                    "sa": "default",
                }
            ],
            "containers": [],
            "components": [],
            "wasm": [],
        }
        tm = ThreatModel()
        cands = diff_surfaces(inv, tm)
        assert any(sc == "hostpath-writable" for _, sc, _ in cands)

    def test_modeled_surface_excluded(self):
        inv = {
            "crds": [
                {"api": "v1", "kind": "Recipe", "ref_fields": ["secretRef"], "url_fields": []}
            ],
            "rbac": [],
            "pods": [],
            "containers": [],
            "components": [],
            "wasm": [],
        }

        class FakeTM:
            entry_points = [{"name": "Recipe CRD"}]
            threats = []

        cands = diff_surfaces(inv, FakeTM())
        assert not any(p.get("kind") == "Recipe" for _, _, p in cands)


class TestProbeSteps:
    def test_materialize_probes(self):
        cands = [
            (
                "operator",
                "crd-cross-ns-ref",
                {"api": "v1alpha1", "kind": "DR", "ref_field": "secretRef"},
            )
        ]
        steps = probe_steps(cands, context="lab")
        assert len(steps) >= 1
        assert steps[0]["technique"] == "novel"
        assert steps[0]["adapter"] == "k8s"


class TestNovelHelpers:
    def test_adapter_for(self):
        assert _adapter_for("operator") == "k8s"
        assert _adapter_for("container") == "container"
        assert _adapter_for("wasm") == "wasm"
        assert _adapter_for("unknown") == "k8s"

    def test_target_for_operator(self):
        t = _target_for("operator", {"context": "lab", "tenant_ns": "ns"})
        assert t["context"] == "lab"

    def test_target_for_wasm(self):
        t = _target_for("wasm", {"artifact": "p.wasm"})
        assert t["artifact"] == "p.wasm"


# ======================================================================
# PLAN
# ======================================================================


class TestStepFromPoc:
    def test_yaml_manifest(self):
        f = Finding(id="F1", title="test", severity="high")
        poc = PoC(
            lang="yaml",
            body="apiVersion: v1\nkind: Pod\nmetadata:\n  namespace: app",
            source_field="evidence",
        )
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app"])
        step = _step_from_poc("s1", f, poc, scope)
        assert step is not None
        assert step.verb == "apply-manifest"
        assert step.adapter == "k8s"

    def test_kubectl_raw(self):
        f = Finding(id="F1", title="test", severity="high")
        poc = PoC(lang="bash", body="kubectl get secrets -n kube-system", source_field="evidence")
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["*"])
        step = _step_from_poc("s1", f, poc, scope)
        assert step is not None
        assert step.verb == "raw"

    def test_curl_as_manifest_content_or_resource_name_is_not_an_http_command(self):
        finding = Finding(id="F1", title="test", severity="high")
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app"])
        manifest = PoC(
            "yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: curl\n"
            "data:\n  command: 'curl https://example.test'",
            "evidence",
        )
        kubectl = PoC("bash", "kubectl get pod curl -n app", "evidence")
        assert _step_from_poc("s1", finding, manifest, scope).verb == "apply-manifest"
        assert _step_from_poc("s2", finding, kubectl, scope).verb == "raw"

    def test_curl_http_preserves_destination_method_and_path(self):
        f = Finding(id="F1", title="HTTP exposure", severity="high")
        poc = PoC(
            lang="bash",
            body="curl -sS -X PATCH 'https://app.example:8443/api/test?q=1'\n",
            source_field="evidence",
        )
        scope = Scope(modes={"explicit"}, selected_contexts=("second",))
        scope.clusters["first"] = ClusterScope(context="first", namespaces=["*"])
        scope.clusters["second"] = ClusterScope(
            context="second", namespaces=["app"], explicit_namespaces={"app"}
        )
        scope.http_targets = (HttpTarget(context="second", host="app.example", namespace="app"),)
        step = _step_from_poc("s1", f, poc, scope)
        assert step is not None and step.technique == "replay"
        assert step.cmd is None and step.payload is None
        assert step.target["context"] == "second"
        assert step.target["resource"] == "http_targets"
        assert step.target["http"]["url"] == "https://app.example:8443"
        assert step.target["http"]["path"] == "/api/test?q=1"
        assert step.target["http"]["method"] == "PATCH"
        assert step.classification == "destructive"

    @pytest.mark.parametrize("mode", ["direct", "route"])
    def test_curl_without_explicit_port_serializes_as_valid_plan(self, tmp_path, mode):
        from traust_core.v1.models.artifacts import ValidationPlanArtifact

        yaml = pytest.importorskip("yaml")
        finding = Finding(id="F1", title="HTTP exposure", severity="high")
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["app"], explicit_namespaces={"app"}
        )
        scope.http_targets = (
            HttpTarget(
                context="lab",
                host="app.example",
                namespace="app",
                resource="routes" if mode == "route" else "http_targets",
                name="web" if mode == "route" else None,
            ),
        )
        poc = PoC("bash", "curl https://app.example/api/test", "evidence")
        step = _step_from_poc("s1", finding, poc, scope)
        assert step is not None
        path = write_plan([step], [], tmp_path / "plan.yaml", target_name="test", scope=scope)
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        target = document["steps"][0]["target"]
        assert "port" not in target
        assert target["http"]["port"] is None
        ValidationPlanArtifact.from_document(document)

    def test_curl_exact_route_replay_resolves_without_discovery(self):
        from http_endpoints import EndpointResolver, HttpProbe

        finding = Finding(id="F1", title="HTTP exposure", severity="high")
        poc = PoC("bash", "curl -X POST 'https://app.example:8443/api/test?q=1'", "evidence")
        scope = Scope(modes={"explicit"}, selected_contexts=("lab",))
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example:6443",
            namespaces=["*"],
            explicit_namespaces={"*"},
        )
        scope.http_targets = (
            HttpTarget(
                context="lab", host="app.example", namespace="app", resource="routes", name="web"
            ),
        )
        step = _step_from_poc("s1", finding, poc, scope)
        assert step is not None and step.technique == "replay" and step.cmd is None
        assert step.target["resource"] == "routes" and step.target["name"] == "web"
        probe = HttpProbe.model_validate(step.target["http"])
        assert probe.mode == "route" and probe.namespaces == ("app",) and probe.name == "web"
        assert probe.method == "POST" and probe.path == "/api/test?q=1"
        assert probe.url == "https://app.example:8443" and probe.port == 8443

        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if "config" in argv:
                obj = {"clusters": [{"cluster": {"server": "https://api.example:6443"}}]}
            else:
                obj = {
                    "metadata": {"name": "web", "namespace": "app", "uid": "route-1"},
                    "spec": {"host": "app.example", "tls": {}},
                }
            return 0, json.dumps(obj), ""

        endpoint = EndpointResolver(scope, runner, "oc").resolve("lab", probe)
        assert endpoint.origin == "https://app.example:8443"
        assert calls[-1][-4:] == ["routes", "web", "-o", "json"]

    def test_curl_domain_grant_resolves_only_requested_route(self):
        from http_endpoints import EndpointResolver, HttpProbe

        finding = Finding(id="F1", title="HTTP exposure", severity="high")
        poc = PoC("bash", "curl -X PATCH 'https://web.apps.example/api/x?q=1'", "evidence")
        scope = Scope(modes={"explicit"}, selected_contexts=("lab",))
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example:6443",
            namespaces=["*"],
            explicit_namespaces={"*"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
            ),
        )
        scope.clusters["other"] = ClusterScope(
            context="other",
            namespaces=["*"],
            explicit_namespaces={"*"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "other", "domains": ["apps.example"]}]}
            ),
        )
        finding.pocs = [poc]
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, scope, chained=False, novel=False, permit_destructive=True)
        step = next(s for s in steps if s.finding_ref == finding.id)
        assert step.technique == "replay" and step.cmd is None and step.skip is None
        probe = HttpProbe.model_validate(step.target["http"])
        assert step.target["context"] == "lab" and step.target["namespace"] == "app"
        assert probe.mode == "route" and probe.name is None and probe.namespaces == ("app",)
        assert probe.method == "PATCH" and probe.path == "/api/x?q=1"
        assert probe.url == "https://web.apps.example" and probe.port is None

        def runner(argv, **kwargs):
            if "config" in argv:
                obj = {"clusters": [{"cluster": {"server": "https://api.example:6443"}}]}
            else:
                obj = {
                    "items": [
                        {
                            "metadata": {"name": "other", "namespace": "app", "uid": "other-1"},
                            "spec": {"host": "outside.example", "tls": {}},
                        },
                        {
                            "metadata": {"name": "web", "namespace": "app", "uid": "web-1"},
                            "spec": {"host": "web.apps.example", "tls": {}},
                        },
                        {
                            "metadata": {"name": "more", "namespace": "app", "uid": "more-1"},
                            "spec": {"host": "other.apps.example", "tls": {}},
                        },
                    ]
                }
            return 0, json.dumps(obj), ""

        endpoint = EndpointResolver(scope, runner, "oc").resolve("lab", probe)
        assert endpoint.origin == "https://web.apps.example"
        assert endpoint.name == "web" and endpoint.namespace == "app"

    def test_curl_domain_grants_enforce_boundaries_scope_and_ambiguity(self):
        from scope import OffLimit

        finding = Finding(id="F1", title="HTTP exposure", severity="high")
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["*"],
            explicit_namespaces={"*"},
            http_discovery=HttpDiscovery.model_validate(
                {
                    "routes": [
                        {"namespace": "app", "domains": ["apps.example"]},
                        {"namespace": "other", "domains": ["apps.example"]},
                    ]
                }
            ),
        )
        poc = PoC("bash", "curl https://web.apps.example/api/test", "evidence")
        assert _step_from_poc("s1", finding, poc, scope) is None
        scope.off_limits.append(OffLimit(namespace="other"))
        step = _step_from_poc("s1", finding, poc, scope)
        assert step is not None and step.target["namespace"] == "app"
        bad = PoC("bash", "curl https://web.apps.example.evil/api/test", "evidence")
        assert _step_from_poc("s2", finding, bad, scope) is None
        scope.clusters["lab"].verbs_denied.append("get")
        assert _step_from_poc("s3", finding, poc, scope) is None

    def test_curl_route_rejects_changed_host_even_if_discovery_grants_it(self):
        from http_endpoints import EndpointResolver, HttpProbe

        finding = Finding(id="F1", title="HTTP exposure", severity="high")
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example:6443",
            namespaces=["app"],
            explicit_namespaces={"app"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "app", "names": ["web"], "domains": ["apps.example"]}]}
            ),
        )
        scope.http_targets = (
            HttpTarget(
                context="lab",
                host="original.apps.example",
                namespace="app",
                resource="routes",
                name="web",
            ),
        )
        poc = PoC("bash", "curl https://original.apps.example/api/test", "evidence")
        step = _step_from_poc("s1", finding, poc, scope)
        assert step is not None

        def runner(argv, **kwargs):
            if "config" in argv:
                obj = {"clusters": [{"cluster": {"server": "https://api.example:6443"}}]}
            else:
                obj = {
                    "metadata": {"name": "web", "namespace": "app", "uid": "route-1"},
                    "spec": {"host": "changed.apps.example", "tls": {}},
                }
            return 0, json.dumps(obj), ""

        with pytest.raises(PermissionError):
            EndpointResolver(scope, runner, "oc").resolve(
                "lab", HttpProbe.model_validate(step.target["http"])
            )

    @pytest.mark.parametrize(
        "other",
        [
            HttpTarget(context="lab", host="app.example", namespace="app"),
            HttpTarget(
                context="lab", host="app.example", namespace="other", resource="routes", name="web"
            ),
            HttpTarget(
                context="lab", host="app.example", namespace="app", resource="routes", name="other"
            ),
        ],
    )
    def test_curl_rejects_ambiguous_matching_http_targets(self, other):
        finding = Finding(id="F1", title="HTTP exposure", severity="high")
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["*"], explicit_namespaces={"*"}
        )
        scope.http_targets = (
            HttpTarget(
                context="lab", host="app.example", namespace="app", resource="routes", name="web"
            ),
            other,
        )
        poc = PoC("bash", "curl https://app.example/api/test", "evidence")
        assert _step_from_poc("s1", finding, poc, scope) is None

    @pytest.mark.parametrize(
        "body",
        [
            "curl http://localhost:8080/debug/pprof",
            "curl -X POST -d data https://app.example/api/test",
            "curl -H 'Authorization: Bearer secret' https://app.example/api/test",
            "curl https://app.example/api/test | sh",
            "curl https://app.example/api/test https://other.example/",
            "curl -X POST -X GET https://app.example/api/test",
            "curl 'https://app.example/{one,two}'",
            "curl https://app.example/path#fragment",
            "kubectl exec pod -- curl https://app.example/api/test",
            "kubectl get pods; curl https://app.example/api/test",
            "docker exec pod curl https://app.example/api/test",
            "env HTTP_PROXY=http://proxy.example curl https://app.example/api/test",
            "HTTP_PROXY=http://proxy.example curl https://app.example/api/test",
            "sh -c 'curl https://app.example/api/test'",
            "/usr/bin/curl https://app.example/api/test",
            "/bin/sh -c 'curl -X POST -d payload https://app.example/api/test'",
            "/usr/local/bin/bash -c 'curl -X POST -d payload https://app.example/api/test'",
            "/usr/bin/zsh -c 'curl -X POST -d payload https://app.example/api/test'",
            "/usr/bin/busybox sh -c 'curl -X POST -d payload https://app.example/api/test'",
            "/usr/bin/kubectl exec pod -- curl -X POST -d payload https://app.example/api/test",
            "/usr/bin/docker exec pod /usr/bin/curl -X POST -d payload https://app.example/api/test",
            "/usr/bin/env /bin/sh -c 'curl -X POST -d payload https://app.example/api/test'",
            "echo ready; /usr/bin/kubectl exec pod -- curl -X POST -d payload https://app.example/api/test",
            "/bin/sh " + "\\" + "\n" + " -c 'curl -X POST -d payload https://app.example/api/test'",
            "/usr/bin/kubectl exec pod -- " + "\\" + "\r\n" + " curl https://app.example/api/test",
            "cu" + "\\" + "\n" + "rl -X POST -d payload https://app.example/api/test",
            "printf '%s' "
            + "\\" * 2
            + "\n"
            + "curl -X POST -d payload https://app.example/api/test",
            "printf '%s' "
            + "\\" * 2
            + "\r\n"
            + "curl -X POST -d payload https://app.example/api/test",
            "./tools/curl -X POST -d payload https://app.example/api/test",
        ],
    )
    def test_unsupported_curl_never_becomes_a_different_probe(self, body, tmp_path):
        finding = Finding(
            id="F1",
            title="HTTP exposure",
            severity="high",
            cwes=["CWE-200"],
            description="GET /api/unrelated",
            pocs=[PoC("bash", body, "evidence")],
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["app"], explicit_namespaces={"app"}
        )
        scope.http_targets = (HttpTarget(context="lab", host="app.example", namespace="app"),)
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == "F1"]
        assert len(planned) == 1
        assert planned[0].skip == "unsupported-curl-poc"
        assert planned[0].cmd is None and planned[0].technique == "skip"
        assert "http" not in planned[0].target
        assert not any(step.technique == "adapted" for step in planned)
        path = write_plan(planned, [], tmp_path / "plan.yaml", target_name="fixture", scope=scope)
        results, _ = run(path, scope, tmp_path, second_pass_novel=False)
        assert len(results) == 1
        assert results[0].verdict == "not_attempted"
        assert results[0].scope_reason == "unsupported-curl-poc"

    def test_unsupported_curl_is_recorded_even_with_another_replay(self):
        finding = Finding(
            id="F1",
            title="HTTP exposure",
            severity="high",
            cwes=["CWE-200"],
            pocs=[
                PoC("bash", "kubectl get pod app -n app", "evidence"),
                PoC("bash", "curl -d data https://app.example/api", "evidence"),
                PoC("bash", "sh -c 'curl https://app.example/api'", "evidence"),
            ],
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["app"], explicit_namespaces={"app"}
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert sum(step.verb == "raw" and step.technique == "replay" for step in planned) == 1
        assert sum(step.skip == "unsupported-curl-poc" for step in planned) == 2
        assert not any(step.technique == "adapted" for step in planned)

    @pytest.mark.parametrize("preconditions", [["authenticated user"], ["arbitrary setup"]])
    def test_curl_does_not_drop_or_fabricate_preconditions(self, preconditions):
        finding = Finding(
            id="F1", title="HTTP exposure", severity="high", preconditions=preconditions
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app"])
        scope.http_targets = (HttpTarget(context="lab", host="app.example", namespace="app"),)
        poc = PoC("bash", "curl https://app.example/api/test", "evidence")
        assert _step_from_poc("s1", finding, poc, scope) is None
        finding.pocs = [poc]
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1 and planned[0].skip == "unsupported-curl-poc"
        assert not planned[0].preconditions

    @pytest.mark.parametrize(
        "claim", ["authenticated session", "CSRF attack", "requires authentication"]
    )
    def test_curl_does_not_drop_identity_requirements_from_claim(self, claim):
        finding = Finding(id="F1", title=claim, severity="high")
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app"])
        scope.http_targets = (HttpTarget(context="lab", host="app.example", namespace="app"),)
        poc = PoC("bash", "curl https://app.example/api/test", "evidence")
        assert _step_from_poc("s1", finding, poc, scope) is None

    def test_no_match(self):
        f = Finding(id="F1", title="test", severity="high")
        poc = PoC(lang="text", body="some description without a command", source_field="desc")
        scope = Scope()
        step = _step_from_poc("s1", f, poc, scope)
        assert step is None


class TestAdaptedStep:
    def test_cwe_918_ssrf_no_path_skipped(self):
        # v0.4.x removed CWE-918 from CWE_ADAPTED (RESIDUAL §B: 77 inconclusives
        # from unfilled {port}/{path}). A bare SSRF finding with no extractable
        # endpoint must NOT produce a generic step.
        f = Finding(id="F1", title="SSRF", severity="high", cwes=["CWE-918"])
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["*"])
        assert _adapted_step("s1", f, scope) is None
        assert _http_adapted_step("s1", f, scope, tm=None) is None

    def test_cwe_918_ssrf_with_path_adapted(self):
        # Conditional: when (method, path) ARE extractable from the finding
        # text, _http_adapted_step emits a concrete port-forward+http step.
        f = Finding(
            id="F1",
            title="SSRF",
            severity="high",
            cwes=["CWE-918"],
            description="POST /api/dev-console/webhooks/{a,b,c} fetches caller URL",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["openshift-console"],
            explicit_namespaces={"openshift-console"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "openshift-console", "domains": ["apps.example"]}]}
            ),
        )
        step = _http_adapted_step("s1", f, scope, tm=None)
        assert step is not None
        assert step.technique == "adapted"
        assert step.verb == "port-forward+http"
        assert step.target["path"] == "/api/dev-console/webhooks/a"
        assert step.target["namespace"] == "openshift-console"
        assert step.cmd is None
        assert step.classification == "destructive"
        assert step.target["http"]["method"] == "POST"
        assert step.target["http"]["path"] == "/api/dev-console/webhooks/a"
        assert step.target["http"]["authenticate"] is False

    def test_authenticated_csrf_claim_keeps_preconditions(self):
        finding = Finding(
            id="F2",
            title="CSRF by authenticated user on HTTP endpoint",
            severity="high",
            cwes=["CWE-200"],
            description="POST /api/v1/action",
        )
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app"])
        step = _http_adapted_step("s2", finding, scope, tm=None)
        assert step is not None and step.cmd is None
        assert step.target["http"]["authenticate"] is True
        assert step.target["http"]["csrf"] is True

    def test_http_planner_respects_context_selection(self):
        finding = Finding(
            id="F3",
            title="HTTP exposure",
            severity="high",
            cwes=["CWE-200"],
            description="GET /metrics",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["first"] = ClusterScope(context="first", namespaces=["one"])
        scope.clusters["second"] = ClusterScope(
            context="second",
            namespaces=["two"],
            explicit_namespaces={"two"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "two", "domains": ["apps.example"]}]}
            ),
        )
        assert _http_adapted_step("s3", finding, scope, tm=None) is None
        scope.selected_contexts = ("second",)
        step = _http_adapted_step("s3", finding, scope, tm=None)
        assert step is not None
        assert step.target["context"] == "second"
        assert step.target["http"]["namespaces"] == ["two"]

    def test_http_planner_retains_multiple_namespace_candidates(self):
        finding = Finding(
            id="F4",
            title="HTTP exposure",
            severity="high",
            cwes=["CWE-200"],
            description="GET /metrics",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["app-a", "app-b"],
            explicit_namespaces={"app-a", "app-b"},
            http_discovery=HttpDiscovery.model_validate(
                {
                    "routes": [
                        {"namespace": "app-a", "domains": ["apps.example"]},
                        {"namespace": "app-b", "domains": ["apps.example"]},
                    ]
                }
            ),
        )
        step = _http_adapted_step("s4", finding, scope, tm=None)
        assert step is not None
        assert step.target["namespace"] is None
        assert step.target["http"]["namespaces"] == ["app-a", "app-b"]

    def test_exact_route_namespace_resolves_without_discovery(self):
        from http_endpoints import EndpointResolver, HttpProbe

        finding = Finding(
            id="F5",
            title="HTTP exposure",
            severity="high",
            cwes=["CWE-200"],
            description="GET /api/v1/test",
        )
        scope = Scope(modes={"explicit"}, selected_contexts=("lab",))
        scope.clusters["other"] = ClusterScope(context="other", namespaces=["*"])
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example:6443",
            namespaces=["*"],
            explicit_namespaces={"*"},
        )
        scope.http_targets = (
            HttpTarget(
                context="lab", host="app.example", namespace="app", resource="routes", name="app"
            ),
            HttpTarget(
                context="other",
                host="other.example",
                namespace="other",
                resource="routes",
                name="other",
            ),
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        step = next(s for s in steps if s.finding_ref == finding.id)
        assert step.skip is None and step.target["context"] == "lab"
        assert step.target["http"]["namespaces"] == ["app"]

        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if "config" in argv:
                obj = {"clusters": [{"cluster": {"server": "https://api.example:6443"}}]}
            else:
                obj = {
                    "metadata": {"name": "app", "namespace": "app", "uid": "route-1"},
                    "spec": {"host": "app.example"},
                }
            return 0, json.dumps(obj), ""

        endpoint = EndpointResolver(scope, runner, "oc").resolve(
            "lab", HttpProbe.model_validate(step.target["http"])
        )
        assert endpoint.origin == "http://app.example"
        assert calls[-1][-4:] == ["routes", "app", "-o", "json"]

    def test_hints_cannot_grant_or_suppress_allowed_candidates(self):
        from scope import OffLimit

        finding = Finding(
            id="F6",
            title="HTTP exposure",
            severity="high",
            cwes=["CWE-200"],
            description="GET /api/v1/test",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["allowed"],
            explicit_namespaces={"allowed"},
            namespace_hints=["allowed", "outside", "no-grant", "blocked", "bad*"],
            http_discovery=HttpDiscovery.model_validate(
                {
                    "routes": [
                        {"namespace": "allowed", "domains": ["apps.example"]},
                        {"namespace": "outside", "domains": ["apps.example"]},
                        {"namespace": "blocked", "domains": ["apps.example"]},
                    ]
                }
            ),
        )
        scope.off_limits.append(OffLimit(namespace="blocked"))
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        step = next(s for s in steps if s.finding_ref == finding.id)
        assert step.skip is None
        assert step.target["http"]["namespaces"] == ["allowed"]

        scope.clusters["lab"].namespaces = ["*"]
        scope.clusters["lab"].explicit_namespaces = {"*"}
        step = _http_adapted_step("s1", finding, scope, tm=None)
        assert step is not None
        assert step.target["http"]["namespaces"] == ["allowed", "outside"]

    def test_candidates_respect_actual_http_method_denies(self):
        from scope import OffLimit

        finding = Finding(
            id="F8",
            title="HTTP endpoint",
            severity="high",
            cwes=["CWE-200"],
            description="POST /api/action",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["*"],
            explicit_namespaces={"*"},
            namespace_hints=["allowed", "denied"],
            http_discovery=HttpDiscovery.model_validate(
                {
                    "routes": [
                        {"namespace": "allowed", "domains": ["apps.example"]},
                        {"namespace": "denied", "domains": ["apps.example"]},
                    ]
                }
            ),
        )
        scope.off_limits.append(OffLimit(namespace="denied", resource="routes", verb="create"))
        step = _http_adapted_step("s1", finding, scope, tm=None)
        assert step is not None and step.target["http"]["method"] == "POST"
        assert step.target["http"]["namespaces"] == ["allowed"]

    def test_wildcard_service_uses_scoped_hints_without_loopback_grant(self):
        from scope import OffLimit

        finding = Finding(
            id="F7",
            title="HTTP debug endpoint",
            severity="high",
            cwes=["CWE-200"],
            description="GET /debug/pprof/",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["*"],
            explicit_namespaces={"*"},
            namespace_hints=["app", "denied"],
        )
        scope.off_limits.append(OffLimit(namespace="denied"))
        step = _http_adapted_step("s1", finding, scope, tm=None)
        assert step is not None
        assert step.target["http"]["mode"] == "service"
        assert step.target["http"]["namespaces"] == ["app"]
        assert not scope.http_targets

    def test_wildcard_monitoring_hint_selects_only_authorized_service(self):
        from scope import OffLimit

        finding = Finding(
            id="F9",
            title="HTTP metrics endpoint",
            severity="high",
            cwes=["CWE-200"],
            description="GET /metrics",
        )
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            namespaces=["*"],
            explicit_namespaces={"*"},
            namespace_hints=["openshift-monitoring"],
        )
        step = _http_adapted_step("s1", finding, scope, tm=None)
        assert step is not None
        assert step.target["http"]["mode"] == "service"
        assert step.target["http"]["namespaces"] == ["openshift-monitoring"]

        scope.off_limits.append(OffLimit(namespace="openshift-monitoring"))
        step = _http_adapted_step("s2", finding, scope, tm=None)
        assert step is not None
        assert "openshift-monitoring" not in step.target["http"]["namespaces"]
        assert step.target["http"]["mode"] == "route"

        scope.off_limits.clear()
        scope.clusters["lab"].namespaces = ["app"]
        scope.clusters["lab"].explicit_namespaces = {"app"}
        step = _http_adapted_step("s3", finding, scope, tm=None)
        assert step is not None
        assert "openshift-monitoring" not in step.target["http"]["namespaces"]
        assert step.target["http"]["mode"] == "route"

    def test_unknown_cwe_no_step(self):
        f = Finding(id="F1", title="test", severity="low", cwes=["CWE-999"])
        scope = Scope()
        step = _adapted_step("s1", f, scope)
        assert step is None


class TestBuildPlan:
    @pytest.fixture
    def simple_inputs(self):
        findings = [
            Finding(
                id="F1",
                title="RBAC over-grant",
                severity="critical",
                cwes=["CWE-269"],
                pocs=[PoC("bash", "kubectl auth can-i --list", "evidence")],
            ),
            Finding(
                id="F2",
                title="FP finding",
                severity="low",
                cwes=["CWE-200"],
                triage_verdict="false_positive",
            ),
        ]
        n = Normalized(target_name="test", source_dir="/tmp", findings=findings)
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(context="lab", namespaces=["app"])
        return n, scope

    def test_replay_steps_generated(self, simple_inputs):
        n, scope = simple_inputs
        steps, _chains = build_plan(n, scope, chained=False, novel=False)
        replay = [s for s in steps if s.technique == "replay"]
        assert len(replay) >= 1
        assert replay[0].finding_ref == "F1"

    def test_fp_skipped(self, simple_inputs):
        n, scope = simple_inputs
        steps, _ = build_plan(n, scope, chained=False, novel=False)
        fp = [s for s in steps if s.finding_ref == "F2"]
        assert all(s.technique == "skip" for s in fp)

    def test_header_spoof_is_not_replaced_by_generic_http_probe(self):
        from http_endpoints import HttpProbe
        from traust_core.v1.models.validation import HttpDiscovery

        finding = Finding(
            id="F3",
            title="X-Forwarded-User spoof",
            severity="high",
            cwes=["CWE-200", "CWE-290"],
            description="GET /api/v1/profile",
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example",
            namespaces=["app"],
            explicit_namespaces={"app"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
            ),
        )
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        assert planned[0].target["http"]["headers"] == {"X-Forwarded-User": "vf-spoof-canary"}
        assert planned[0].target["http"]["mode"] == "route"
        assert planned[0].cmd is None and planned[0].skip is None
        assert HttpProbe.model_validate(planned[0].target["http"]).headers == {
            "X-Forwarded-User": "vf-spoof-canary"
        }

    @pytest.mark.parametrize(
        "header",
        [
            "X-Auth-Request-User",
            "X-Forwarded-Access-Token",
            "X-Api-Key",
            "X-Forwarded-User and X-Api-Key",
        ],
    )
    def test_adapter_owned_spoof_headers_are_explicitly_skipped(self, tmp_path, monkeypatch, header):
        from unittest.mock import Mock

        import execute

        finding = Finding(
            id="F3",
            title=f"{header} spoof",
            severity="high",
            cwes=["CWE-200", "CWE-290"],
            description="GET /api/v1/profile",
            triage_verdict="needs_review",
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example",
            namespaces=["app"],
            explicit_namespaces={"app"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
            ),
        )
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        step = planned[0]
        assert step.technique == "skip"
        assert step.skip == "spoof-header-adapter-owned"
        assert step.triage_was_needs_review is True
        assert "http" not in step.target

        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps({"steps": [step.to_dict()]}))
        new_adapter = Mock()
        monkeypatch.setattr(execute, "new_adapter", new_adapter)
        results, audit = run(plan_path, scope, tmp_path, second_pass_novel=False)
        assert results[0].verdict == "not_attempted"
        assert results[0].scope_reason == "spoof-header-adapter-owned"
        assert json.loads(audit.path.read_text())["verdict"] == "not_attempted"
        new_adapter.assert_not_called()

    def test_unavailable_spoof_probe_is_not_replaced_by_generic_adaptation(self):
        finding = Finding(
            id="F3",
            title="X-Forwarded-User spoof",
            severity="high",
            cwes=["CWE-200", "CWE-348"],
            description="GET /api/v1/profile",
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        steps, _ = build_plan(normalized, Scope(), chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        assert planned[0].technique == "skip"
        assert planned[0].skip == "spoof-probe-unavailable"

    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
    @pytest.mark.parametrize("source", ["poc", "adapted"])
    @pytest.mark.parametrize("permit_destructive", [False, True])
    def test_http_plan_requires_opt_in_for_uncompensated_writes(
        self, method, source, permit_destructive
    ):
        finding = Finding(
            id="F4",
            title="HTTP endpoint exposure",
            severity="high",
            cwes=["CWE-200"],
            description=f"{method} /api/test",
            pocs=(
                [PoC("bash", f"curl -X {method} https://app.example/api/test", "evidence")]
                if source == "poc"
                else []
            ),
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example",
            namespaces=["app"],
            explicit_namespaces={"app"},
            http_discovery=HttpDiscovery.model_validate(
                {"routes": [{"namespace": "app", "domains": ["apps.example"]}]}
            ),
        )
        scope.http_targets = (HttpTarget(context="lab", host="app.example", namespace="app"),)
        steps, _ = build_plan(
            normalized, scope, chained=False, novel=False, permit_destructive=permit_destructive
        )
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        step = planned[0]
        assert step.technique == ("replay" if source == "poc" else "adapted")
        assert step.target["http"]["method"] == method
        assert step.classification == ("safe" if method == "GET" else "destructive")
        assert step.skip == (
            "destructive-not-permitted" if method != "GET" and not permit_destructive else None
        )

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    @pytest.mark.parametrize("permit_destructive", [False, True])
    def test_manual_structured_http_write_is_classified_before_review(
        self, tmp_path, monkeypatch, method, permit_destructive
    ):
        import plan

        pytest.importorskip("yaml")
        monkeypatch.setattr(plan, "_resolve_manual_pocs_dir", lambda: tmp_path)
        (tmp_path / "F4.yaml").write_text(
            json.dumps(
                {
                    "verb": "port-forward+http",
                    "classification": "safe",
                    "target": {
                        "context": "lab",
                        "namespace": "app",
                        "resource": "http_targets",
                        "http": {
                            "mode": "direct",
                            "url": "https://app.example",
                            "method": method,
                            "namespaces": ["app"],
                        },
                    },
                }
            )
        )
        finding = Finding(id="F4", title="Manual HTTP check", severity="high")
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", api="https://api.example", namespaces=["app"], explicit_namespaces={"app"}
        )
        steps, _ = build_plan(
            normalized, scope, chained=False, novel=False, permit_destructive=permit_destructive
        )
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        assert planned[0].technique == "replay"
        assert planned[0].classification == "destructive"
        assert planned[0].skip == (None if permit_destructive else "destructive-not-permitted")

    def test_namespace_less_direct_poc_precheck_uses_exact_origin(self, monkeypatch):
        finding = Finding(
            id="F5",
            title="Direct HTTP endpoint",
            severity="high",
            pocs=[PoC("bash", "curl https://app.example:8443/api/test", "evidence")],
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", api="https://api.example", namespaces=["app"], explicit_namespaces={"app"}
        )
        scope.http_targets = (HttpTarget(context="lab", host="app.example"),)
        actions = []
        original = scope.is_in_scope

        def capture(action):
            actions.append(action)
            return original(action)

        monkeypatch.setattr(scope, "is_in_scope", capture)
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        assert planned[0].technique == "replay"
        assert planned[0].skip is None
        assert planned[0].target["http"]["url"] == "https://app.example:8443"
        direct_actions = [action for action in actions if action.resource == "http_targets"]
        assert direct_actions
        assert all(action.url == "https://app.example:8443" for action in direct_actions)

    def test_unnamed_node_probe_prechecks_the_scoped_list(self):
        from traust_core.v1.models.validation import HttpDiscovery

        finding = Finding(
            id="F4",
            title="hostNetwork HTTP listener on 10250",
            severity="high",
            cwes=["CWE-200"],
            description="GET /metrics",
        )
        normalized = Normalized(target_name="test", source_dir="/tmp", findings=[finding])
        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example",
            namespaces=["app"],
            explicit_namespaces={"app"},
            http_discovery=HttpDiscovery.model_validate({"nodes": {"networks": ["10.0.0.0/24"]}}),
        )
        steps, _ = build_plan(normalized, scope, chained=False, novel=False)
        planned = [step for step in steps if step.finding_ref == finding.id]
        assert len(planned) == 1
        assert planned[0].target["http"]["mode"] == "node"
        assert planned[0].target["http"]["name"] is None
        assert planned[0].skip is None

    def test_novel_placeholder(self, simple_inputs):
        n, scope = simple_inputs
        steps, _ = build_plan(n, scope, novel=True)
        assert any(s.verb == "placeholder" and s.technique == "novel" for s in steps)

    def test_destructive_not_permitted(self, simple_inputs):
        n, scope = simple_inputs
        # Add a finding that generates a destructive step
        n.findings.append(
            Finding(
                id="F3",
                title="Delete test",
                severity="high",
                cwes=["CWE-269"],
                pocs=[PoC("bash", "kubectl delete clusterrole cluster-admin", "evidence")],
            )
        )
        _steps, _ = build_plan(n, scope, permit_destructive=False, chained=False, novel=False)
        # The destructive step should be classified and marked
        # Note: 'kubectl delete' is parsed as 'raw' verb which may classify as destructive
        # via heuristic

    def test_write_plan(self, tmp_path, simple_inputs):
        n, scope = simple_inputs
        steps, chains = build_plan(n, scope, chained=False, novel=False)
        out = tmp_path / "plan.yaml"
        write_plan(steps, chains, out, target_name="test", scope=scope)
        assert out.exists()

    def test_summarize(self, simple_inputs):
        n, scope = simple_inputs
        steps, _ = build_plan(n, scope)
        text = summarize(steps)
        assert "Attack plan summary" in text


# ======================================================================
# EXECUTE
# ======================================================================


class TestAuditLog:
    def test_append_and_sha(self, tmp_path):
        log = AuditLog(tmp_path / "audit.jsonl")
        log.append(step_id="s1", verdict="confirmed")
        log.append(step_id="s2", verdict="refuted")
        lines = log.path.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["step_id"] == "s1"
        sha = log.sha256()
        assert len(sha) == 64


class TestStepAction:
    def test_from_dict(self):
        step = {"adapter": "k8s", "verb": "get", "target": {"context": "lab", "namespace": "app"}}
        a = _step_action(step)
        assert a.adapter == "k8s"
        assert a.context == "lab"
        assert a.namespace == "app"


class TestExecuteRun:
    def test_scope_gating(self, tmp_path):
        plan = {
            "steps": [
                {
                    "id": "s1",
                    "adapter": "k8s",
                    "verb": "get",
                    "target": {"context": "prod", "namespace": "kube-system"},
                    "classification": "safe",
                    "expected": "test",
                }
            ],
        }
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan))
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["app"], explicit_namespaces={"app"}
        )
        results, _audit = run(plan_path, scope, tmp_path, second_pass_novel=False)
        assert results[0].verdict == "blocked_by_scope"

    def test_precondition_failure(self, tmp_path):
        plan = {
            "steps": [
                {
                    "id": "s1",
                    "adapter": "k8s",
                    "verb": "noop",
                    "target": {},
                    "classification": "safe",
                    "skip": "test-skip",
                },
                {
                    "id": "s2",
                    "adapter": "k8s",
                    "verb": "get",
                    "target": {"context": "lab", "namespace": "app"},
                    "classification": "safe",
                    "expected": "test",
                    "preconditions": ["s1"],
                },
            ],
        }
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan))
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["app"], explicit_namespaces={"app"}
        )
        results, _ = run(plan_path, scope, tmp_path, second_pass_novel=False)
        assert results[1].verdict == "not_attempted"
        assert "precondition-failed" in results[1].scope_reason

    def test_destructive_blocked(self, tmp_path):
        plan = {
            "steps": [
                {
                    "id": "s1",
                    "adapter": "k8s",
                    "verb": "delete",
                    "target": {"context": "lab", "namespace": "app"},
                    "classification": "destructive",
                    "expected": "test",
                }
            ],
        }
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan))
        scope = Scope()
        scope.clusters["lab"] = ClusterScope(
            context="lab", namespaces=["app"], explicit_namespaces={"app"}
        )
        results, _ = run(
            plan_path, scope, tmp_path, permit_destructive=False, second_pass_novel=False
        )
        assert results[0].verdict == "not_attempted"
        assert "destructive" in results[0].scope_reason

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
    @pytest.mark.parametrize("declared", ["safe", "mutating"])
    @pytest.mark.parametrize("permit_destructive", [False, True])
    def test_structured_http_write_requires_runtime_opt_in(
        self, tmp_path, monkeypatch, method, declared, permit_destructive
    ):
        from unittest.mock import Mock

        from adapters.http import HttpExecutor
        from http_endpoints import Endpoint, EndpointResolver

        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab", api="https://api.example", namespaces=["app"], explicit_namespaces={"app"}
        )
        scope.http_targets = (HttpTarget(context="lab", host="app.example", namespace="app"),)
        endpoint = Endpoint(
            "https://app.example", "lab", "app", "http_targets", "", resolved_api="https://api.example"
        )
        monkeypatch.setattr(EndpointResolver, "resolve", lambda *_: endpoint)
        curl = Mock(return_value=(0, "ok\nvf-http-status:200", ""))
        monkeypatch.setattr(HttpExecutor, "curl", curl)
        step = {
            "id": "http",
            "adapter": "k8s",
            "verb": "port-forward+http",
            "classification": declared,
            "target": {
                "context": "lab",
                "namespace": "app",
                "resource": "http_targets",
                "http": {
                    "mode": "direct",
                    "url": "https://app.example",
                    "method": method,
                    "path": "/api/test",
                    "namespaces": ["app"],
                },
            },
        }
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps({"steps": [step]}))
        results, audit = run(
            plan_path, scope, tmp_path, permit_destructive=permit_destructive, second_pass_novel=False
        )
        result = results[0]
        is_write = method in {"POST", "PUT", "PATCH", "DELETE"}
        assert result.classification == ("destructive" if is_write else declared)
        if is_write and not permit_destructive:
            assert result.verdict == "not_attempted"
            assert result.scope_reason == "destructive-not-permitted"
            curl.assert_not_called()
        else:
            assert result.verdict not in {"blocked_by_scope", "not_attempted"}
            curl.assert_called_once()
            args = curl.call_args.args[0]
            if method == "HEAD":
                assert "--head" in args
            else:
                assert args[args.index("-X") + 1] == method
        audit_records = [json.loads(line) for line in audit.path.read_text().splitlines()]
        assert audit_records[-1]["classification"] == result.classification

    @pytest.mark.parametrize(
        "method,denied_verb",
        [("POST", "create"), ("PUT", "update"), ("PATCH", "patch"), ("DELETE", "delete")],
    )
    def test_destructive_opt_in_does_not_override_http_scope(
        self, tmp_path, monkeypatch, method, denied_verb
    ):
        from unittest.mock import Mock

        from adapters.http import HttpExecutor
        from http_endpoints import Endpoint, EndpointResolver

        scope = Scope(modes={"explicit"})
        scope.clusters["lab"] = ClusterScope(
            context="lab",
            api="https://api.example",
            namespaces=["app"],
            explicit_namespaces={"app"},
            verbs_denied=[denied_verb],
        )
        endpoint = Endpoint(
            "https://app.example", "lab", "app", "http_targets", "", resolved_api="https://api.example"
        )
        monkeypatch.setattr(EndpointResolver, "resolve", lambda *_: endpoint)
        curl = Mock()
        monkeypatch.setattr(HttpExecutor, "curl", curl)
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "steps": [
                        {
                            "id": "http",
                            "adapter": "k8s",
                            "verb": "port-forward+http",
                            "classification": "safe",
                            "target": {
                                "context": "lab",
                                "namespace": "app",
                                "resource": "http_targets",
                                "http": {
                                    "mode": "direct",
                                    "url": "https://app.example",
                                    "method": method,
                                    "namespaces": ["app"],
                                },
                            },
                        }
                    ]
                }
            )
        )
        results, _ = run(
            plan_path, scope, tmp_path, permit_destructive=True, second_pass_novel=False
        )
        assert results[0].classification == "destructive"
        assert results[0].verdict == "blocked_by_scope"
        assert denied_verb in results[0].scope_reason
        curl.assert_not_called()


# ======================================================================
# ADAPTERS — VERDICT LOGIC
# ======================================================================


class TestK8sVerdict:
    def test_forbidden_refuted(self):
        assert (
            K8sAdapter._verdict("raw", 1, "Error from server (Forbidden): pods is forbidden", "")
            == "refuted"
        )

    def test_unauthorized_refuted(self):
        assert (
            K8sAdapter._verdict("get", 1, "error: You must be logged in (Unauthorized)", "")
            == "refuted"
        )

    def test_success_with_signal_confirmed(self):
        assert K8sAdapter._verdict("apply-manifest", 0, "pod/vf-canary created", "") == "confirmed"

    def test_success_no_signal_inconclusive(self):
        assert K8sAdapter._verdict("raw", 0, "some output", "") == "inconclusive"

    def test_failure_inconclusive(self):
        assert K8sAdapter._verdict("raw", 1, "connection refused", "") == "inconclusive"

    # ---- v0.4.3 tightening (derived from signal-ambiguous corpus) ----

    def test_rbac_can_i_yes_with_reason(self):
        assert (
            K8sAdapter._verdict("rbac-can-i", 0, "yes - RBAC allowed by ClusterRoleBinding x", "")
            == "confirmed"
        )

    def test_rbac_can_i_no_with_reason(self):
        assert K8sAdapter._verdict("rbac-can-i", 1, "no - no RBAC policy matched", "") == "refuted"

    def test_http_200_unauth_confirmed(self):
        assert (
            K8sAdapter._verdict(
                "port-forward+http",
                0,
                "vf-http-status:200",
                "Unauthenticated controller-runtime metrics endpoint exposed on :8080",
            )
            == "confirmed"
        )

    def test_http_403_unauth_refuted(self):
        assert (
            K8sAdapter._verdict(
                "port-forward+http",
                0,
                "403",
                "Unauthenticated /scrape?target= permits caller-directed outbound TCP",
            )
            == "refuted"
        )

    def test_http_000_inconclusive(self):
        assert (
            K8sAdapter._verdict(
                "port-forward+http",
                7,
                "vf-http-status:000",
                "SSRF via Provider.spec.url",
            )
            == "inconclusive"
        )

    def test_http_200_expected_denial_refuted(self):
        assert (
            K8sAdapter._verdict(
                "port-forward+http",
                0,
                "200",
                "request should be rejected with 403",
            )
            == "refuted"
        )

    def test_exec_uid0_confirmed(self):
        assert (
            K8sAdapter._verdict(
                "exec",
                0,
                "uid=0(root) gid=0(root) groups=0(root)",
                "container escape to root on node",
            )
            == "confirmed"
        )

    def test_exec_permission_denied_refuted(self):
        assert (
            K8sAdapter._verdict(
                "exec",
                1,
                "touch: cannot touch '/host/x': Permission denied",
                "writable hostPath mount",
            )
            == "refuted"
        )

    def test_apply_crb_escalation_confirmed(self):
        assert (
            K8sAdapter._verdict(
                "apply-manifest",
                0,
                "clusterrolebinding.rbac.authorization.k8s.io/my-cronjob created",
                "default-namespace pod creator → full cluster-admin on ACM hub",
            )
            == "confirmed"
        )

    def test_apply_expected_denied_but_created_refuted(self):
        assert (
            K8sAdapter._verdict(
                "apply-manifest",
                0,
                "pod/evil created",
                "admission webhook should have rejected the privileged pod",
            )
            == "refuted"
        )

    def test_raw_secret_base64_confirmed(self):
        assert (
            K8sAdapter._verdict(
                "raw",
                0,
                "data:\n  token: " + _B64_WRAPPED_JWT_HEADER,
                "Any principal with read access → harvest hub kubeconfig token",
            )
            == "confirmed"
        )

    def test_raw_no_resources_refuted(self):
        assert (
            K8sAdapter._verdict(
                "raw",
                0,
                "No resources found in traust-foo namespace.",
                "read all cluster Secrets",
            )
            == "refuted"
        )

    def test_raw_crb_created_escalation_confirmed(self):
        assert (
            K8sAdapter._verdict(
                "raw",
                0,
                "clusterrolebinding.rbac.authorization.k8s.io/nhc-pwn created",
                "Wildcard verbs on clusterroles ⇒ operator SA is cluster-admin-equivalent",
            )
            == "confirmed"
        )

    def test_network_probe_refused_refuted(self):
        assert (
            K8sAdapter._verdict(
                "network-probe",
                1,
                "nc: connect to 10.0.0.1 port 6379 (tcp) failed: Connection refused",
                "redis port reachable from tenant pod",
            )
            == "refuted"
        )

    # ---- v0.4.4 substring-FP guards (MANUAL-REVIEW-FLAGS.md) ---------

    def test_notfound_is_inconclusive_not_confirmed(self):
        # kube-rbac-proxy/FIND-001 ×5: ``upstream``/``token`` in expected
        # substring-matched inside the NotFound error text.
        assert (
            K8sAdapter._verdict(
                "raw",
                1,
                'Error from server (NotFound): pods "kube-rbac-proxy-abc" not found',
                "upstream metrics token returned without bearer auth",
            )
            == "inconclusive"
        )

    def test_get_notfound_inconclusive(self):
        assert (
            K8sAdapter._verdict(
                "get",
                1,
                'Error from server (NotFound): secrets "vf-probe" not found',
                "secret token leaked to caller",
            )
            == "inconclusive"
        )

    def test_exec_no_such_file_inconclusive(self):
        assert (
            K8sAdapter._verdict(
                "exec",
                1,
                "cat: /etc/shadow: No such file or directory",
                "credential file readable from container",
            )
            == "inconclusive"
        )

    def test_serviceaccount_does_not_match_account(self):
        # Word-boundary: ``account`` (claim vocab) must not match inside
        # ``serviceaccount`` (k8s error text).
        assert (
            K8sAdapter._verdict(
                "raw",
                0,
                "system:serviceaccount:openshift-monitoring:prometheus-k8s",
                "default service account credentials grant cluster read",
            )
            == "inconclusive"
        )

    def test_oauth_proxy_not_valid_for_pod_inconclusive(self):
        # devspaces oauth-proxy/FIND-002: ``oauth`` in expected matched
        # inside ``oauth-proxy`` in the container-not-valid error.
        assert (
            K8sAdapter._verdict(
                "exec",
                1,
                "error: container oauth-proxy is not valid for pod che-gateway-7d9f",
                "oauth proxy passes upstream bearer token to backend",
            )
            == "inconclusive"
        )

    def test_pf_http_could_not_resolve_host_inconclusive(self):
        assert (
            K8sAdapter._verdict(
                "port-forward+http",
                6,
                "curl: (6) Could not resolve host: kube-rbac-proxy.svc",
                "upstream returns 200 with bearer token echoed",
            )
            == "inconclusive"
        )

    def test_stop_word_alone_never_confirms(self):
        # ``error``/``server``/``request`` are claim-vocab stop words —
        # a lone match in observed must not confirm.
        assert (
            K8sAdapter._verdict(
                "raw",
                0,
                "Error from server (InternalError): an error on the request",
                "server error on malformed client request",
            )
            == "inconclusive"
        )

    def test_non_stop_strong_token_still_confirms(self):
        # Regression guard: a real distinctive token still confirms.
        assert (
            K8sAdapter._verdict(
                "raw",
                0,
                "configmap traust-ssrf-probe-hit created in tenant ns",
                "traust-ssrf-probe-hit configmap appears in tenant namespace",
            )
            == "confirmed"
        )


class TestK8sNormalizers:
    def test_manifest_drops_prose_doc(self):
        raw = "This is a description with a colon: oops\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
        out = K8sAdapter._normalize_manifest(raw)
        assert "kind: ConfigMap" in out
        assert "oops" not in out

    def test_manifest_keeps_only_k8s_objects(self):
        raw = "---\n[1,2,3]\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
        out = K8sAdapter._normalize_manifest(raw)
        assert "kind: Secret" in out
        assert "[1,2,3]" not in out and "- 1" not in out

    def test_manifest_quotes_colon_value(self):
        raw = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  annotations:\n    a: b\n"
        # round-trip should still parse
        out = K8sAdapter._normalize_manifest(raw)
        assert "kind: ConfigMap" in out

    def test_manifest_unparseable_passthrough(self):
        raw = "not yaml: [unclosed"
        assert K8sAdapter._normalize_manifest(raw) == raw


class TestContainerVerdict:
    def test_permission_denied_refuted(self):
        assert ContainerAdapter._verdict(1, "sh: permission denied", "") == "refuted"

    def test_operation_not_permitted_refuted(self):
        assert ContainerAdapter._verdict(1, "operation not permitted", "") == "refuted"

    def test_forbidden_refuted(self):
        assert ContainerAdapter._verdict(1, "Forbidden: cannot access", "") == "refuted"

    def test_success_with_canary_confirmed(self):
        assert ContainerAdapter._verdict(0, "vf-canary created", "") == "confirmed"

    def test_success_cap_sys_admin_confirmed(self):
        assert (
            ContainerAdapter._verdict(0, "CapEff: 00000000a80425fb  CAP_SYS_ADMIN", "")
            == "confirmed"
        )

    def test_success_socket_confirmed(self):
        assert ContainerAdapter._verdict(0, "srw-rw---- 1 root docker.sock", "") == "confirmed"

    def test_success_no_signal_inconclusive(self):
        assert ContainerAdapter._verdict(0, "some output", "") == "inconclusive"

    def test_negative_expected_refuted(self):
        assert ContainerAdapter._verdict(0, "ls: no such file", "no socket present") == "refuted"

    def test_negative_expected_not_found_refuted(self):
        assert ContainerAdapter._verdict(0, "", "not accessible from container") == "refuted"

    def test_failure_no_denial_inconclusive(self):
        assert ContainerAdapter._verdict(1, "Error: No such container", "") == "inconclusive"


class TestWasmVerdict:
    def test_trap_confirmed(self):
        assert WasmAdapter._verdict(1, "wasm trap: unreachable", "") == "confirmed"

    def test_out_of_bounds_confirmed(self):
        assert WasmAdapter._verdict(1, "out of bounds memory access", "") == "confirmed"

    def test_fuel_limit_refuted(self):
        assert WasmAdapter._verdict(1, "error: insufficient fuel", "") == "refuted"

    def test_not_allowed_refuted(self):
        assert WasmAdapter._verdict(1, "capability not available", "") == "refuted"

    def test_wasi_error_refuted(self):
        assert WasmAdapter._verdict(1, "wasi error: permission denied", "") == "refuted"

    def test_clean_exit_expected_enforces_refuted(self):
        assert WasmAdapter._verdict(0, "fuel consumed: 1000", "engine enforces fuel") == "refuted"

    def test_clean_exit_expected_limited_refuted(self):
        assert WasmAdapter._verdict(0, "ok", "preopens limited to declared dirs") == "refuted"

    def test_clean_exit_with_imports_confirmed(self):
        assert WasmAdapter._verdict(0, '(import "wasi_snapshot_preview1")', "") == "confirmed"

    def test_failure_generic_inconclusive(self):
        assert WasmAdapter._verdict(1, "some error", "") == "inconclusive"

    def test_clean_exit_generic_inconclusive(self):
        assert WasmAdapter._verdict(0, "ok", "") == "inconclusive"


class TestAdapterClassify:
    def test_safe_verb(self):
        ad = K8sAdapter()
        assert ad.classify("get") == "safe"
        assert ad.classify("rbac-can-i") == "safe"

    def test_mutating_verb(self):
        ad = K8sAdapter()
        assert ad.classify("apply-manifest") == "mutating"
        assert ad.classify("exec") == "mutating"

    def test_destructive_verb(self):
        ad = K8sAdapter()
        assert ad.classify("delete") == "destructive"

    def test_heuristic_on_raw_cmd(self):
        ad = K8sAdapter()
        assert ad.classify("unknown", cmd="kubectl delete pods foo") == "destructive"
        assert ad.classify("unknown", cmd="kubectl apply -f manifest.yaml") == "mutating"
        assert ad.classify("unknown", cmd="kubectl get pods") == "safe"


class TestAdapterRegistry:
    def test_get_adapter(self):
        assert isinstance(get_adapter("k8s"), K8sAdapter)
        assert isinstance(get_adapter("container"), ContainerAdapter)
        assert isinstance(get_adapter("wasm"), WasmAdapter)

    def test_unknown_adapter(self):
        with pytest.raises(ValueError, match="unknown adapter"):
            get_adapter("unknown")

    def test_new_adapter_independence(self):
        a1 = new_adapter("k8s")
        a2 = new_adapter("k8s")
        assert a1 is not a2
        # Independent rate-limit state
        a1._last_mutating["ctx"] = 999.0
        assert a2._last_mutating.get("ctx") is None


class TestK8sRateLimitThreadSafety:
    def test_rate_limit_lock_exists(self):
        ad = K8sAdapter()
        assert hasattr(ad, "_rate_lock")
        assert isinstance(ad._rate_lock, type(threading.Lock()))

    def test_independent_instances(self):
        a1 = K8sAdapter()
        a2 = K8sAdapter()
        a1._last_mutating["ctx"] = 100.0
        assert "ctx" not in a2._last_mutating


# ======================================================================
# REPORT
# ======================================================================


class TestBuildValidationJson:
    @pytest.fixture
    def report_inputs(self):
        findings = [
            Finding(id="F1", title="RBAC", severity="high", cwes=["CWE-269"]),
            Finding(id="F2", title="SSRF", severity="medium", cwes=["CWE-918"]),
        ]
        n = Normalized(
            target_name="test-repo",
            source_dir="/tmp",
            source_reports=[
                {"kind": "security-audit", "path": "/tmp/audit.json", "sha256": "a" * 64}
            ],
            findings=findings,
        )
        results = [
            StepResult(
                step_id="s1",
                adapter="k8s",
                verb="raw",
                target={},
                classification="safe",
                verdict="confirmed",
                observed="canary found",
                finding_ref="F1",
            ),
            StepResult(
                step_id="s2",
                adapter="k8s",
                verb="port-forward+http",
                target={},
                classification="safe",
                verdict="refuted",
                observed="401 Forbidden",
                finding_ref="F2",
            ),
        ]
        chains = [
            Chain(
                chain_id="CHAIN-001",
                entry_point="API",
                terminal_asset="SA Token",
                path=[Node("entry", "API"), Node("finding", "F1"), Node("asset", "SA Token")],
                finding_ids=["F1"],
                capabilities=["sa-token"],
                mitre=["T1528"],
            ),
        ]
        scope = Scope()
        scope.modes.add("explicit")
        scope.engagement = "test-engagement"
        return n, scope, results, chains

    def test_json_structure(self, report_inputs):
        n, scope, results, chains = report_inputs
        doc = build_validation_json(
            n,
            scope,
            results,
            chains,
            fingerprints=[],
            audit_path="audit.jsonl",
            audit_sha256="b" * 64,
            flags=["--replay-only"],
            approval={"mode": "interactive"},
        )
        assert doc["title"]
        assert doc["metadata"]["scope_binding_mode"] == "explicit"
        assert doc["summary"]["by_verdict"]["confirmed"] == 1
        assert doc["summary"]["by_verdict"]["refuted"] == 1

    def test_verdict_rollup(self, report_inputs):
        n, scope, results, chains = report_inputs
        doc = build_validation_json(
            n,
            scope,
            results,
            chains,
            fingerprints=[],
            audit_path="a",
            audit_sha256="b" * 64,
            flags=[],
            approval={},
        )
        vf = {v["source_id"]: v for v in doc["validated_findings"]}
        assert vf["F1"]["verdict"] == "confirmed"
        assert vf["F2"]["verdict"] == "refuted"


class TestRenderMarkdown:
    def test_basic_render(self):
        doc = {
            "title": "Live Validation Report — test",
            "metadata": {
                "date": "2026-01-01",
                "harness_version": "1.0-abc",
                "scope_binding_mode": "explicit",
                "scope_source": "test",
                "engagement": "E1",
                "authorized_by": "user@test",
                "approval": {"mode": "interactive"},
            },
            "source_reports": [{"kind": "security-audit", "path": "a.json", "sha256": "a" * 64}],
            "summary": {
                "by_verdict": {
                    "confirmed": 1,
                    "refuted": 0,
                    "inconclusive": 0,
                    "blocked_by_scope": 0,
                    "not_attempted": 0,
                },
                "by_technique": {"replay": 1},
                "novel_count": 0,
                "chain_count": 0,
                "highest_impact_chain": None,
            },
            "validated_findings": [
                {
                    "source_id": "F1",
                    "verdict": "confirmed",
                    "technique": "replay",
                    "title": "Test finding",
                    "claimed_severity": "high",
                    "evidence": [],
                }
            ],
            "attack_chains": [],
            "novel_findings": [],
            "execution_log_ref": "audit.jsonl",
            "execution_log_sha256": "b" * 64,
        }
        md = render_markdown(doc)
        assert "# Live Validation Report" in md
        assert "CONFIRMED" in md
        assert "F1" in md


class TestStripNones:
    def test_removes_nones(self):
        d = {"a": 1, "b": None, "c": {"d": None, "e": 2}}
        _strip_nones(d)
        assert "b" not in d
        assert "d" not in d["c"]
        assert d["c"]["e"] == 2

    def test_handles_lists(self):
        d = {"a": [{"b": None, "c": 1}]}
        _strip_nones(d)
        assert "b" not in d["a"][0]


class TestWriteReport:
    def test_write_files(self, tmp_path):
        doc = {
            "title": "Live Validation Report — test",
            "metadata": {
                "date": "2026-01-01",
                "harness_version": "1.0",
                "scope_binding_mode": "none",
                "target_fingerprint": [],
                "approval": {},
            },
            "source_reports": [
                {"kind": "security-audit", "path": "opaque:original", "sha256": "a" * 64}
            ],
            "summary": {
                "by_verdict": {
                    "confirmed": 0,
                    "refuted": 0,
                    "inconclusive": 0,
                    "blocked_by_scope": 0,
                    "not_attempted": 0,
                },
                "by_technique": {},
                "novel_count": 0,
                "chain_count": 0,
                "highest_impact_chain": None,
            },
            "validated_findings": [],
            "attack_chains": [],
            "novel_findings": [],
            "execution_log_ref": "audit.jsonl",
        }
        jpath, mpath = write(doc, tmp_path, "test")
        assert jpath.exists()
        assert mpath.exists()
        data = json.loads(jpath.read_text())
        assert data["title"]


class TestHarnessVersion:
    def test_returns_string(self):
        v = harness_version()
        assert isinstance(v, str)
        assert len(v) >= 1
