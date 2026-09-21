#!/usr/bin/env python3
"""Unit tests for validate_report.py and render_report.py."""

import copy
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
from traust_engine.ledger import fingerprint
from traust_engine.reporting.render import render_report
from traust_engine.reporting.validate import (
    ValidationResult,
    check_finding_identity,
    collect_report_files,
    cross_validate,
    load_schema,
    strict_checks,
    validate_report,
)


def _valid_report():
    """Return a minimal report dict that passes all validation."""
    return {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-05-21",
            "scope": "First-party Go source (cmd/, pkg/), Kubernetes manifests, Dockerfiles",
            # Required as of 2026-08-13: metadata.repository is the first field
            # of the fingerprint payload, so a valid report must carry one.
            "repository": "https://github.com/example/widget-operator",
        },
        "executive_summary": {
            "prose": (
                "The Widget Operator manages resources in OpenShift clusters. "
                "This assessment identified 2 findings across the codebase."
            ),
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {
                "level": "critical",
                "definition": "Remote attacker achieves node-root or cluster-admin without authentication.",
            },
            {
                "level": "high",
                "definition": "Authenticated user escalates privileges across namespace boundaries.",
            },
            {
                "level": "medium",
                "definition": "Requires elevated prerequisites or enables denial of service.",
            },
            {
                "level": "low",
                "definition": "Hardening gap or best-practice deviation with no direct exploitability.",
            },
        ],
        "findings": [
            {
                "id": "TEST-001",
                "fingerprint": "751cd01c845b9a42fbe6ccd09ed16586d183a46216f14527bf36ce7802aa9357",
                "title": "SSRF via Webhook Annotation",
                "severity": "high",
                "cwes": ["CWE-918"],
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "42-58"}],
                "description": (
                    "The admission webhook reads a destination URL from a pod annotation "
                    "and makes an HTTP POST without validating against an allow-list."
                ),
                "remediation": "Validate the callback URL against a configurable allow-list of permitted hosts.",
            },
            {
                "id": "TEST-002",
                "fingerprint": "52931d51ade87b6825b3faec555debe756f31403e8c222e6a28b3fdc91e38ae1",
                "title": "Unbounded Request Body Read",
                "severity": "medium",
                "cwes": ["CWE-770"],
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "30-35"}],
                "description": (
                    "The admission webhook reads the entire request body with io.ReadAll "
                    "without setting a size limit, enabling memory exhaustion."
                ),
                "remediation": "Replace io.ReadAll with io.LimitReader(r.Body, maxBodySize).",
            },
        ],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 1, "finding_ids": ["TEST-001"]},
            {"severity": "medium", "count": 1, "finding_ids": ["TEST-002"]},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "P0",
                "action": "Implement URL allow-list validation for webhook callbacks",
                "addresses": ["TEST-001"],
            },
            {
                "priority": "P1",
                "action": "Add io.LimitReader to admission webhook body read",
                "addresses": ["TEST-002"],
            },
        ],
    }


SCHEMA = load_schema()


def _schema_errors(report):
    """Run JSON Schema validation and return list of error messages."""
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
    return [e.message for e in validator.iter_errors(report)]


def _cross_errors(report):
    """Run cross-validation and return the ValidationResult."""
    result = ValidationResult(file_path="<test>")
    cross_validate(report, result)
    return result


# ---------------------------------------------------------------------------
# Good report
# ---------------------------------------------------------------------------


class TestValidReport(unittest.TestCase):
    def test_valid_report_passes_schema(self):
        errors = _schema_errors(_valid_report())
        self.assertEqual(errors, [])

    def test_valid_report_passes_cross_checks(self):
        result = _cross_errors(_valid_report())
        self.assertEqual(result.errors, [])

    def test_valid_report_strict_warnings(self):
        result = ValidationResult(file_path="<test>")
        strict_checks(_valid_report(), result)
        self.assertEqual(result.errors, [])
        warn_text = " ".join(result.warnings)
        self.assertIn("dependency_audit", warn_text)
        self.assertIn("negative_results", warn_text)
        self.assertIn("footer", warn_text)
        self.assertIn("CVSS", warn_text)

    def test_full_round_trip_via_file(self):
        report = _valid_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            from traust_engine.reporting.validate import validate_report

            r = validate_report(path, SCHEMA)
            self.assertTrue(r.passed, r.errors)
        finally:
            Path(path).unlink()


# ---------------------------------------------------------------------------
# Schema violations — one per test
# ---------------------------------------------------------------------------


class TestSchemaViolations(unittest.TestCase):
    def _mutate(self, fn):
        """Deep-copy the valid report, apply fn, return schema errors."""
        r = copy.deepcopy(_valid_report())
        fn(r)
        return _schema_errors(r)

    def test_missing_title(self):
        errors = self._mutate(lambda r: r.pop("title"))
        self.assertTrue(any("'title' is a required property" in e for e in errors))

    def test_bad_title_no_security_keyword(self):
        errors = self._mutate(lambda r: r.__setitem__("title", "My Cool Project Report"))
        self.assertTrue(any("does not match" in e for e in errors))

    def test_missing_metadata_date(self):
        errors = self._mutate(lambda r: r["metadata"].pop("date"))
        self.assertTrue(any("'date' is a required property" in e for e in errors))

    def test_invalid_date_format(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("date", "not-a-date"))
        self.assertTrue(
            any("is not a" in e.lower() or "format" in e.lower() for e in errors), errors
        )

    def test_missing_scope(self):
        errors = self._mutate(lambda r: r["metadata"].pop("scope"))
        self.assertTrue(any("'scope' is a required property" in e for e in errors))

    def test_scope_too_short(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("scope", "x"))
        self.assertTrue(any("too short" in e or "minLength" in e for e in errors), errors)

    def test_invalid_severity_level(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("severity", "extreme"))
        self.assertTrue(any("'extreme' is not one of" in e for e in errors))

    def test_empty_cwes(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("cwes", []))
        self.assertTrue(any("non-empty" in e or "too short" in e for e in errors), errors)

    def test_bad_cwe_format(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("cwes", ["not-a-cwe"]))
        self.assertTrue(any("does not match" in e for e in errors))

    def test_empty_locations(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("locations", []))
        self.assertTrue(any("non-empty" in e or "too short" in e for e in errors), errors)

    def test_description_too_short(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("description", "short"))
        self.assertTrue(any("too short" in e or "minLength" in e for e in errors), errors)

    def test_missing_findings_summary(self):
        errors = self._mutate(lambda r: r.pop("findings_summary"))
        self.assertTrue(any("'findings_summary' is a required property" in e for e in errors))

    def test_missing_remediation_roadmap(self):
        errors = self._mutate(lambda r: r.pop("remediation_roadmap"))
        self.assertTrue(any("'remediation_roadmap' is a required property" in e for e in errors))

    def test_additional_property_rejected(self):
        errors = self._mutate(lambda r: r.__setitem__("bogus_field", "oops"))
        self.assertTrue(
            any("additional properties" in e.lower() or "unevaluated" in e.lower() for e in errors),
            errors,
        )

    def test_severity_criteria_too_few(self):
        errors = self._mutate(
            lambda r: r.__setitem__("severity_criteria", r["severity_criteria"][:2])
        )
        self.assertTrue(any("too short" in e or "minItems" in e for e in errors), errors)

    def test_missing_finding_title(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("title"))
        self.assertTrue(any("'title' is a required property" in e for e in errors))

    def test_missing_finding_remediation(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("remediation"))
        self.assertTrue(any("'remediation' is a required property" in e for e in errors))

    def test_invalid_cvss_score_too_high(self):
        def add_bad_cvss(r):
            r["findings"][0]["cvss"] = {"score": 11.0, "vector": "AV:N/AC:L"}

        errors = self._mutate(add_bad_cvss)
        self.assertTrue(any("11.0" in e or "maximum" in e for e in errors), errors)

    def test_invalid_capec_format(self):
        def add_bad_capec(r):
            r["findings"][0]["capec"] = ["not-capec"]

        errors = self._mutate(add_bad_capec)
        self.assertTrue(any("does not match" in e for e in errors))

    def test_roadmap_action_too_short(self):
        errors = self._mutate(lambda r: r["remediation_roadmap"][0].__setitem__("action", "fix"))
        self.assertTrue(any("too short" in e or "minLength" in e for e in errors), errors)


# ---------------------------------------------------------------------------
# Cross-validation violations
# ---------------------------------------------------------------------------


class TestCrossValidation(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_report())
        fn(r)
        return _cross_errors(r)

    def test_duplicate_finding_id(self):
        result = self._mutate(lambda r: r["findings"][1].__setitem__("id", "TEST-001"))
        self.assertTrue(any("Duplicate finding ID" in e for e in result.errors), result.errors)

    def test_severity_count_mismatch(self):
        result = self._mutate(lambda r: r["findings_summary"][1].__setitem__("count", 5))
        self.assertTrue(any("count is 5" in e for e in result.errors), result.errors)

    def test_summary_ids_length_mismatch(self):
        def mutate(r):
            r["findings_summary"][1]["count"] = 2

        result = self._mutate(mutate)
        self.assertTrue(any("finding_ids has 1 entries" in e for e in result.errors), result.errors)

    def test_summary_references_unknown_id(self):
        def mutate(r):
            r["findings_summary"][1]["finding_ids"] = ["GHOST-999"]

        result = self._mutate(mutate)
        self.assertTrue(
            any("unknown finding ID: GHOST-999" in e for e in result.errors), result.errors
        )

    def test_finding_missing_from_summary(self):
        def mutate(r):
            r["findings_summary"][2]["finding_ids"] = []
            r["findings_summary"][2]["count"] = 0

        result = self._mutate(mutate)
        self.assertTrue(any("not listed" in e.lower() for e in result.errors), result.errors)

    def test_roadmap_references_unknown_id(self):
        def mutate(r):
            r["remediation_roadmap"][0]["addresses"] = ["NONEXISTENT-001"]

        result = self._mutate(mutate)
        self.assertTrue(
            any("unknown finding ID: NONEXISTENT-001" in e for e in result.errors), result.errors
        )

    def test_missing_mandatory_severity_criterion(self):
        def mutate(r):
            r["severity_criteria"] = [c for c in r["severity_criteria"] if c["level"] != "high"]
            # keep minItems happy by adding a duplicate
            r["severity_criteria"].append(r["severity_criteria"][0])

        result = self._mutate(mutate)
        self.assertTrue(
            any("missing mandatory level: high" in e for e in result.errors), result.errors
        )

    def test_executive_summary_count_mismatch(self):
        def mutate(r):
            r["executive_summary"]["severity_counts"]["high"] = 5

        result = self._mutate(mutate)
        self.assertTrue(
            any("executive_summary.severity_counts[high]" in e for e in result.errors),
            result.errors,
        )

    def test_executive_summary_counts_match_findings(self):
        result = self._mutate(lambda r: None)
        es_errors = [e for e in result.errors if "executive_summary.severity_counts" in e]
        self.assertEqual(es_errors, [])


# ---------------------------------------------------------------------------
# Directory validation (rglob)
# ---------------------------------------------------------------------------


class TestDirectoryValidation(unittest.TestCase):
    def test_directory_mode_finds_nested_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "product" / "repo"
            nested.mkdir(parents=True)
            report_path = nested / "repo-security-audit.json"
            report_path.write_text(json.dumps(_valid_report()), encoding="utf-8")

            target = Path(tmpdir)
            files = sorted(target.rglob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].name, "repo-security-audit.json")

            r = validate_report(str(files[0]), SCHEMA)
            self.assertTrue(r.passed, r.errors)

    def test_collect_report_files_finds_nested_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "product" / "repo"
            nested.mkdir(parents=True)
            (nested / "repo-security-audit.json").write_text("{}", encoding="utf-8")
            (Path(tmpdir) / "top-level.json").write_text("{}", encoding="utf-8")

            files = collect_report_files(tmpdir)
            names = [f.name for f in files]
            self.assertIn("repo-security-audit.json", names)
            self.assertIn("top-level.json", names)
            self.assertEqual(len(files), 2)


# ---------------------------------------------------------------------------
# Renderer smoke test
# ---------------------------------------------------------------------------


class TestRenderer(unittest.TestCase):
    def test_render_produces_expected_sections(self):
        report = _valid_report()
        report["negative_results"] = [
            {"area": "SQL Injection", "result": "No issues found."},
        ]
        report["footer"] = "End of report."
        md = render_report(report)

        self.assertIn("# Security Assessment", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Severity Criteria", md)
        self.assertIn("## 3. Detailed Findings", md)
        self.assertIn("## 4. Findings Summary", md)
        self.assertIn("## 5. Remediation Roadmap", md)
        self.assertIn("Negative Results", md)
        self.assertIn("*End of report.*", md)

    def test_render_includes_finding_details(self):
        md = render_report(_valid_report())

        self.assertIn("TEST-001", md)
        self.assertIn("TEST-002", md)
        self.assertIn("CWE-918", md)
        self.assertIn("CWE-770", md)
        self.assertIn("**High**", md)
        self.assertIn("**Medium**", md)
        self.assertIn("handler.go:42-58", md)

    def test_render_evidence_code_block(self):
        report = copy.deepcopy(_valid_report())
        report["findings"][0]["evidence"] = [
            {"language": "go", "code": "http.Post(url, ct, body)", "caption": "Vulnerable call"},
        ]
        md = render_report(report)
        self.assertIn("```go", md)
        self.assertIn("http.Post(url, ct, body)", md)
        self.assertIn("*Vulnerable call*", md)

    def test_render_metadata_table_format(self):
        report = copy.deepcopy(_valid_report())
        report["metadata"]["repository"] = "github.com/example/test"
        report["metadata"]["commit"] = "abc123"
        md = render_report(report)
        self.assertIn("| **Date**", md)
        self.assertIn("| **Repository**", md)

    def test_render_metadata_inline_format(self):
        md = render_report(_valid_report())
        self.assertIn("**Date:** 2026-05-21", md)
        self.assertIn("**Scope:**", md)


# ---------------------------------------------------------------------------
# 0.15.0 consistency conventions
# ---------------------------------------------------------------------------


def _consistency_report():
    """Fixture upgraded to the 0.15.0 conventions (canonical IDs, commit,
    harness_version) so the CONSISTENCY_MIN_VERSION gates fire."""
    r = copy.deepcopy(_valid_report())
    r["metadata"]["commit"] = "abcdef0123456789abcdef0123456789abcdef01"
    r["metadata"]["additional"] = {"harness_version": "0.15.0-1234567"}
    text = json.dumps(r)
    text = text.replace("TEST-001", "TEST_WIDGET-abcdef0-001")
    text = text.replace("TEST-002", "TEST_WIDGET-abcdef0-002")
    r = json.loads(text)
    for f in r["findings"]:
        f["validation_status"] = "not_verified"
    r["peach_isolation_review"] = {
        "applicable": False,
        "rationale": "Single-tenant operator: one deployment serves exactly one cluster and trust domain.",
    }
    return r


class TestConsistencyGates(unittest.TestCase):
    """Hard cross-validation gates for harness >= 0.15.0."""

    def test_consistency_fixture_passes(self):
        result = _cross_errors(_consistency_report())
        self.assertEqual(result.errors, [])

    def test_missing_peach_review_is_error_at_0_15(self):
        r = _consistency_report()
        del r["peach_isolation_review"]
        result = _cross_errors(r)
        self.assertTrue(any("peach_isolation_review is required" in e for e in result.errors))

    def test_missing_peach_review_not_error_pre_0_15(self):
        r = _consistency_report()
        del r["peach_isolation_review"]
        r["metadata"]["additional"]["harness_version"] = "0.14.0-1234567"
        result = _cross_errors(r)
        self.assertFalse(any("peach_isolation_review" in e for e in result.errors))

    def test_missing_validation_status_is_error_at_0_15(self):
        r = _consistency_report()
        del r["findings"][0]["validation_status"]
        result = _cross_errors(r)
        self.assertTrue(any("validation_status is required" in e for e in result.errors))


class TestStrictConventions(unittest.TestCase):
    """Strict-mode warnings added with the 0.15.0 conventions."""

    def _warnings(self, report):
        result = ValidationResult(file_path="<test>")
        strict_checks(report, result)
        return result.warnings

    def test_repository_url_must_parse_org_repo(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["repository"] = "https://github.com/someorg"
        self.assertTrue(
            any("metadata.repository" in w and "does not parse" in w for w in self._warnings(r))
        )
        r["metadata"]["repository"] = "free text about Azure repos"
        self.assertTrue(any("does not parse" in w for w in self._warnings(r)))
        r["metadata"]["repository"] = ""
        self.assertTrue(any("metadata.repository missing" in w for w in self._warnings(r)))
        # accepted shapes: plain, <>-wrapped, dot-leading repo, gitlab nesting
        for ok in (
            "https://github.com/org/repo",
            "<https://github.com/org/repo>",
            "https://github.com/org/.github",
            "https://gitlab.example.com/service/iac-declarations",
        ):
            r["metadata"]["repository"] = ok
            self.assertFalse(any("repository" in w for w in self._warnings(r)), ok)

    def test_no_cvss_warning_for_informational(self):
        r = copy.deepcopy(_valid_report())
        r["findings"][1]["severity"] = "informational"
        warns = self._warnings(r)
        self.assertTrue(any("TEST-001" in w and "CVSS" in w for w in warns))
        self.assertFalse(any("TEST-002" in w and "CVSS" in w for w in warns))

    def test_attack_pattern_warning_on_high_only(self):
        warns = self._warnings(_valid_report())
        self.assertTrue(any("TEST-001" in w and "attack_pattern" in w for w in warns))
        self.assertFalse(any("TEST-002" in w and "attack_pattern" in w for w in warns))

    def test_all_confirmed_warning(self):
        r = copy.deepcopy(_valid_report())
        r["findings"] = [
            dict(r["findings"][0], id=f"TEST-{i:03d}", validation_status="confirmed")
            for i in range(1, 6)
        ]
        warns = self._warnings(r)
        self.assertTrue(any("'confirmed'" in w and "not_verified" in w for w in warns))

    def test_mixed_statuses_no_overclaim_warning(self):
        r = copy.deepcopy(_valid_report())
        r["findings"] = [
            dict(
                r["findings"][0],
                id=f"TEST-{i:03d}",
                validation_status="confirmed" if i > 1 else "not_verified",
            )
            for i in range(1, 6)
        ]
        warns = self._warnings(r)
        self.assertFalse(any("'confirmed'" in w and "not_verified" in w for w in warns))

    def test_off_vocabulary_category_warning_at_0_15(self):
        r = _consistency_report()
        r["findings"][0]["category"] = "Improper Widget Management"
        r["findings"][1]["category"] = "Supply Chain"  # normalizes to supply-chain
        warns = self._warnings(r)
        self.assertTrue(any("Improper Widget Management" in w for w in warns))
        self.assertFalse(any("Supply Chain" in w for w in warns))

    def test_no_category_warning_pre_0_15(self):
        r = copy.deepcopy(_valid_report())
        r["findings"][0]["category"] = "Improper Widget Management"
        warns = self._warnings(r)
        self.assertFalse(any("vocabulary" in w for w in warns))

    def test_implausible_date_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = "2023-03-22"
        warns = self._warnings(r)
        self.assertTrue(any("audit execution date" in w for w in warns))

    def test_stale_date_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = (datetime.now(UTC).date() - timedelta(days=10)).isoformat()
        warns = self._warnings(r)
        self.assertTrue(any("audit execution date" in w for w in warns))

    def test_current_date_no_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = datetime.now(UTC).date().isoformat()
        warns = self._warnings(r)
        self.assertFalse(any("audit execution date" in w for w in warns))

    def test_yesterday_no_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
        warns = self._warnings(r)
        self.assertFalse(any("audit execution date" in w for w in warns))

    def test_short_peach_rationale_warning(self):
        r = copy.deepcopy(_valid_report())
        r["peach_isolation_review"] = {"applicable": False, "rationale": "single tenant"}
        warns = self._warnings(r)
        self.assertTrue(any("rationale" in w for w in warns))

    def test_loc_breakdown_warning_at_0_15(self):
        r = _consistency_report()
        r["metadata"]["loc_reviewed"] = "1234"
        warns = self._warnings(r)
        self.assertTrue(any("loc_breakdown" in w for w in warns))


class TestRendererNumbering(unittest.TestCase):
    def test_scanner_correlation_numbered(self):
        report = copy.deepcopy(_valid_report())
        report["scanner_correlation"] = [{"tool": "Trivy", "result": "not configured"}]
        md = render_report(report)
        self.assertIn("## 6. Scanner Correlation", md)


# ---------------------------------------------------------------------------
# Remediation verification reports (verification.schema.json)
# ---------------------------------------------------------------------------

from traust_engine.reporting.validate import build_registry, cross_validate_verification

from traust.paths import SCHEMA_DIR

VERIFICATION_SCHEMA = load_schema(SCHEMA_DIR / "verification.schema.json")
REGISTRY = build_registry()

ORIGINAL_SHA = "abcdef0123456789abcdef0123456789abcdef01"
PATCHED_SHA = "1234567890abcdef1234567890abcdef12345678"
FIX_SHA = "feedfacefeedfacefeedfacefeedfacefeedface"


def _valid_verification_report():
    """Return a minimal verification report that passes all validation."""
    return {
        "title": "sg-core Remediation Verification",
        "metadata": {
            "date": "2026-07-10",
            "harness_version": "0.17.0-1234567",
            "original_report": "findings/openstack-operator/sg-core/sg-core-security-audit.json",
            "original_commit": ORIGINAL_SHA,
            "patched_commit": PATCHED_SHA,
            "patched_ref": "pull/42/head",
            "repository": "https://github.com/openstack-k8s-operators/sg-core",
        },
        "summary": {
            "total_findings": 2,
            "by_verdict": {
                "resolved": 1,
                "partially_resolved": 1,
                "unresolved": 0,
                "new_approach": 0,
                "regression": 0,
                "false_positive": 0,
                "risk_accepted": 0,
            },
            "regressions": 1,
        },
        "verified_findings": [
            {
                "original_id": "SG_CORE-abcdef0-001",
                "original_title": "SSRF via Webhook Annotation",
                "original_severity": "high",
                "verdict": "resolved",
                "remediation_commits": [
                    {
                        "sha": FIX_SHA,
                        "short_sha": FIX_SHA[:7],
                        "date": "2026-06-15T10:00:00+00:00",
                        "author": "Jane Dev <jane@example.com>",
                        "subject": "Validate webhook URL against allow-list (#42)",
                        "pr_number": 42,
                        "relevance": "direct",
                    }
                ],
                "unattributed": False,
                "evidence": {
                    "original_code": "http.Post(url, ct, body)",
                    "patched_code": "if !allowlist.Match(url) { return errDenied }",
                    "explanation": (
                        "Webhook callback URLs are now validated against a "
                        "configurable allow-list before any request is made."
                    ),
                    "framework_reference": "CWE-918",
                },
                "disposition_rationale": None,
                "residual_risk": None,
                "residual_severity": None,
            },
            {
                "original_id": "SG_CORE-abcdef0-002",
                "original_title": "Unbounded Request Body Read",
                "original_severity": "medium",
                "verdict": "partially_resolved",
                "remediation_commits": [
                    {
                        "sha": FIX_SHA,
                        "short_sha": FIX_SHA[:7],
                        "date": "2026-06-15T10:00:00+00:00",
                        "author": "Jane Dev <jane@example.com>",
                        "subject": "Validate webhook URL against allow-list (#42)",
                        "pr_number": 42,
                        "relevance": "partial",
                    }
                ],
                "unattributed": False,
                "evidence": {
                    "original_code": "body, _ := io.ReadAll(r.Body)",
                    "patched_code": "body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))",
                    "explanation": (
                        "The admission path now bounds the body read, but the "
                        "metrics path still calls io.ReadAll unbounded."
                    ),
                    "framework_reference": "CWE-770",
                },
                "disposition_rationale": None,
                "residual_risk": "Metrics endpoint body read remains unbounded.",
                "residual_severity": "low",
            },
        ],
        "regressions": [
            {
                "id": "SG_CORE-1234567-REG-001",
                "title": "Allow-list bypass via URL userinfo",
                "severity": "medium",
                "cwes": ["CWE-918"],
                "cvss": {
                    "score": 5.3,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                },
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "60-72"}],
                "description": (
                    "The new allow-list matcher compares the raw authority "
                    "before stripping userinfo, so https://allowed@evil.example "
                    "bypasses the check."
                ),
                "remediation": "Parse the URL and compare url.Hostname() only.",
                "evidence": [{"code": "if allowlist.Match(u.Host) {", "language": "go"}],
                "introduced_by": FIX_SHA,
            }
        ],
        "commit_timeline": [
            {
                "sha": FIX_SHA[:7],
                "full_sha": FIX_SHA,
                "date": "2026-06-15T10:00:00+00:00",
                "author": "Jane Dev <jane@example.com>",
                "subject": "Validate webhook URL against allow-list (#42)",
                "pr_number": 42,
                "addresses": ["SG_CORE-abcdef0-001", "SG_CORE-abcdef0-002"],
            }
        ],
        "recommendations": ["Bound the metrics endpoint body read to close SG_CORE-abcdef0-002."],
    }


def _verification_schema_errors(report):
    validator = jsonschema.Draft202012Validator(
        VERIFICATION_SCHEMA,
        format_checker=jsonschema.FormatChecker(),
        registry=REGISTRY,
    )
    return [e.message for e in validator.iter_errors(report)]


def _verification_cross(report):
    result = ValidationResult(file_path="<test>")
    cross_validate_verification(report, result)
    return result


class TestVerificationSchema(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_verification_report())
        fn(r)
        return _verification_schema_errors(r)

    def test_valid_report_passes_schema(self):
        self.assertEqual(_verification_schema_errors(_valid_verification_report()), [])

    def test_valid_report_passes_cross_checks(self):
        result = _verification_cross(_valid_verification_report())
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_valid_report_round_trip_via_file(self):
        report = _valid_verification_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            r = validate_report(path, VERIFICATION_SCHEMA, registry=REGISTRY)
            self.assertTrue(r.passed, r.errors)
        finally:
            Path(path).unlink()

    def test_unknown_verdict_rejected(self):
        errors = self._mutate(lambda r: r["verified_findings"][0].__setitem__("verdict", "fixed"))
        self.assertTrue(any("'fixed' is not one of" in e for e in errors), errors)

    def test_short_original_commit_rejected(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("original_commit", "abcdef0"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_regression_id_format_enforced(self):
        errors = self._mutate(lambda r: r["regressions"][0].__setitem__("id", "REG-001"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_regression_requires_introduced_by(self):
        errors = self._mutate(lambda r: r["regressions"][0].pop("introduced_by"))
        self.assertTrue(any("'introduced_by' is a required property" in e for e in errors), errors)

    def test_missing_by_verdict_key_rejected(self):
        errors = self._mutate(lambda r: r["summary"]["by_verdict"].pop("false_positive"))
        self.assertTrue(any("'false_positive' is a required property" in e for e in errors), errors)

    def test_evidence_requires_explanation(self):
        errors = self._mutate(lambda r: r["verified_findings"][0]["evidence"].pop("explanation"))
        self.assertTrue(any("'explanation' is a required property" in e for e in errors), errors)


class TestVerificationCrossChecks(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_verification_report())
        fn(r)
        return _verification_cross(r)

    def test_verdict_count_mismatch(self):
        result = self._mutate(lambda r: r["summary"]["by_verdict"].__setitem__("resolved", 2))
        self.assertTrue(any("by_verdict[resolved]" in e for e in result.errors), result.errors)

    def test_total_findings_mismatch(self):
        result = self._mutate(lambda r: r["summary"].__setitem__("total_findings", 5))
        self.assertTrue(any("summary.total_findings" in e for e in result.errors), result.errors)

    def test_regressions_count_mismatch(self):
        result = self._mutate(lambda r: r["summary"].__setitem__("regressions", 3))
        self.assertTrue(any("summary.regressions" in e for e in result.errors), result.errors)

    def test_duplicate_original_id(self):
        result = self._mutate(
            lambda r: r["verified_findings"][1].__setitem__("original_id", "SG_CORE-abcdef0-001")
        )
        self.assertTrue(any("Duplicate" in e for e in result.errors), result.errors)

    def test_false_positive_requires_disposition_rationale(self):
        def mutate(r):
            f = r["verified_findings"][0]
            f["verdict"] = "false_positive"
            f["remediation_commits"] = []
            f["unattributed"] = True
            r["summary"]["by_verdict"]["resolved"] = 0
            r["summary"]["by_verdict"]["false_positive"] = 1

        result = self._mutate(mutate)
        self.assertTrue(any("disposition_rationale" in e for e in result.errors), result.errors)

    def test_partially_resolved_requires_residual_risk(self):
        result = self._mutate(
            lambda r: r["verified_findings"][1].__setitem__("residual_risk", None)
        )
        self.assertTrue(any("residual_risk" in e for e in result.errors), result.errors)

    def test_resolved_without_commits_or_unattributed(self):
        def mutate(r):
            r["verified_findings"][0]["remediation_commits"] = []

        result = self._mutate(mutate)
        self.assertTrue(any("unattributed" in e for e in result.errors), result.errors)

    def test_unattributed_with_commits_contradiction(self):
        result = self._mutate(lambda r: r["verified_findings"][0].__setitem__("unattributed", True))
        self.assertTrue(any("unattributed is true" in e for e in result.errors), result.errors)

    def test_short_sha_not_prefix(self):
        result = self._mutate(
            lambda r: r["verified_findings"][0]["remediation_commits"][0].__setitem__(
                "short_sha", "1234567"
            )
        )
        self.assertTrue(any("not a prefix" in e for e in result.errors), result.errors)

    def test_timeline_out_of_order(self):
        def mutate(r):
            second = copy.deepcopy(r["commit_timeline"][0])
            second["date"] = "2026-06-01T10:00:00+00:00"
            r["commit_timeline"].append(second)

        result = self._mutate(mutate)
        self.assertTrue(any("chronological" in e for e in result.errors), result.errors)

    def test_timeline_unknown_finding_id(self):
        result = self._mutate(
            lambda r: r["commit_timeline"][0].__setitem__("addresses", ["GHOST-1234567-001"])
        )
        self.assertTrue(any("unknown finding ID" in e for e in result.errors), result.errors)

    def test_regression_shortsha_mismatch_warns(self):
        result = self._mutate(
            lambda r: r["regressions"][0].__setitem__("id", "SG_CORE-0000000-REG-001")
        )
        self.assertTrue(any("patched_commit" in w for w in result.warnings), result.warnings)

    def test_identical_commits_warn(self):
        result = self._mutate(lambda r: r["metadata"].__setitem__("patched_commit", ORIGINAL_SHA))
        self.assertTrue(any("identical" in w for w in result.warnings), result.warnings)

    def test_commit_missing_from_timeline_warns(self):
        result = self._mutate(lambda r: r.__setitem__("commit_timeline", []))
        self.assertTrue(
            any("not in commit_timeline" in w for w in result.warnings),
            result.warnings,
        )


# ---------------------------------------------------------------------------
# Findings disposition layers (layer.schema.json) and cumulative reports
# ---------------------------------------------------------------------------

from traust_engine.ledger import compute_event_id
from traust_engine.reporting.validate import cross_validate_layer

LAYER_SCHEMA = load_schema(SCHEMA_DIR / "layer.schema.json")


def _layer_event(
    finding_ref,
    validity=None,
    resolution=None,
    *,
    ref="https://example.com/mr/17#note_1",
    kind="human",
    source_type="mr_comment",
    at="2026-07-01T10:00:00+00:00",
    ldap=True,
):
    actor = {"kind": kind, "identity": "jdoe@example.com"}
    if kind == "human":
        actor["ldap_verified"] = ldap
    disposition = {}
    if validity:
        disposition["validity"] = validity
    if resolution:
        disposition["resolution"] = resolution
    return {
        "event_id": compute_event_id(ref, finding_ref, validity, resolution),
        "finding_ref": finding_ref,
        "recorded_at": at,
        "source": {"type": source_type, "ref": ref, "actor": actor},
        "disposition": disposition,
        "rationale": "Input is validated upstream in the admission webhook.",
    }


def _valid_layer():
    return {
        "metadata": {
            "audit_report": "test-widget-security-audit.json",
            "audit_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "repository": "https://github.com/example/test-widget",
            "created": "2026-06-01T00:00:00+00:00",
            "updated": "2026-07-02T00:00:00+00:00",
            "harness_version": "0.18.0-1234567",
        },
        "events": [
            _layer_event(
                "TEST_WIDGET-abcdef0-001", validity="false_positive", at="2026-07-01T10:00:00+00:00"
            ),
            _layer_event(
                "TEST_WIDGET-abcdef0-002",
                resolution="resolved",
                ref="rv.json",
                kind="machine",
                source_type="verification_report",
                at="2026-07-02T10:00:00+00:00",
            ),
        ],
        "needs_review": [
            {
                "queued_at": "2026-07-01T12:00:00+00:00",
                "source_ref": "https://example.com/mr/17#note_9",
                "quote": "isn't 002 maybe a false positive?",
                "author": "guest-user",
                "suggested_finding_ref": "TEST_WIDGET-abcdef0-002",
                "suggested_disposition": {"validity": "false_positive"},
                "queue_reason": "ambiguous_statement",
                "status": "pending",
            }
        ],
    }


def _layer_schema_errors(layer):
    validator = jsonschema.Draft202012Validator(
        LAYER_SCHEMA,
        format_checker=jsonschema.FormatChecker(),
        registry=REGISTRY,
    )
    return [e.message for e in validator.iter_errors(layer)]


def _layer_cross(layer):
    result = ValidationResult(file_path="<test>")
    cross_validate_layer(layer, result)
    return result


def _stamp_via_client(layer: dict) -> dict:
    """Stamp Merkle metadata through LedgerClient — the real write path."""
    import tempfile

    from traust_ledger.client import LedgerClient

    layer = copy.deepcopy(layer)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "fixture-findings-layer.json"
        p.write_text(json.dumps(layer), encoding="utf-8")
        LedgerClient(token="test-token", data_dir=td).sign("fixture-findings-layer")
        return json.loads(p.read_text())


class TestLayerValidation(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_layer())
        fn(r)
        return _layer_cross(_stamp_via_client(r))

    def test_valid_layer_passes_schema(self):
        self.assertEqual(_layer_schema_errors(_valid_layer()), [])

    def test_valid_layer_passes_cross_checks(self):
        layer = _stamp_via_client(_valid_layer())
        result = _layer_cross(layer)
        self.assertEqual(result.errors, [])

    def test_layer_without_merkle_root_errors(self):
        # traust-ledger v0.1.3 (plan P6): absent merkle_root is an ERROR, not a
        # warning — a layer with no root has no tamper-evidence at all.
        result = _layer_cross(_valid_layer())
        self.assertTrue(any("merkle_root absent" in e for e in result.errors), result.errors)
        self.assertFalse(any("merkle_root absent" in w for w in result.warnings), result.warnings)

    def test_merkle_layer_passes_when_stamped(self):
        layer = _stamp_via_client(_valid_layer())
        result = _layer_cross(layer)
        self.assertEqual(result.errors, [])
        self.assertTrue(
            all("unsigned" in w for w in result.warnings),
            f"Only expected 'unsigned' warning, got: {result.warnings}",
        )

    def test_merkle_root_mismatch_errors(self):
        layer = _stamp_via_client(_valid_layer())
        layer["events"][0]["finding_ref"] = "TEST_WIDGET-abcdef0-099"
        layer["events"][0]["event_id"] = compute_event_id(
            layer["events"][0]["source"]["ref"],
            "TEST_WIDGET-abcdef0-099",
            layer["events"][0]["disposition"]["validity"],
            layer["events"][0]["disposition"].get("resolution"),
        )
        result = _layer_cross(layer)
        self.assertTrue(any("merkle_root mismatch" in e for e in result.errors), result.errors)

    def test_empty_disposition_rejected_by_schema(self):
        layer = copy.deepcopy(_valid_layer())
        layer["events"][0]["disposition"] = {}
        errors = _layer_schema_errors(layer)
        self.assertTrue(any("non-empty" in e or "minProperties" in e for e in errors), errors)

    def test_tampered_event_id(self):
        result = self._mutate(lambda l: l["events"][0].__setitem__("event_id", "0" * 64))
        self.assertTrue(any("does not match sha256" in e for e in result.errors), result.errors)

    def test_duplicate_event_id(self):
        def mutate(l):
            l["events"].append(copy.deepcopy(l["events"][0]))

        result = self._mutate(mutate)
        self.assertTrue(any("Duplicate event_id" in e for e in result.errors), result.errors)

    def test_out_of_order_events(self):
        def mutate(l):
            l["events"][1]["recorded_at"] = "2026-06-15T10:00:00+00:00"
            e = l["events"][1]
            e["event_id"] = compute_event_id(
                e["source"]["ref"],
                e["finding_ref"],
                e["disposition"].get("validity"),
                e["disposition"].get("resolution"),
            )

        result = self._mutate(mutate)
        self.assertTrue(any("chronological" in e for e in result.errors), result.errors)

    def test_future_dated_event_rejected(self):
        # self-audit -015: a future recorded_at would pin latest-wins
        # adjudication forever; >24h ahead of validation time is an error
        def mutate(l):
            e = l["events"][-1]
            e["recorded_at"] = "2099-01-01T00:00:00+00:00"
            e["event_id"] = compute_event_id(
                e["source"]["ref"],
                e["finding_ref"],
                e["disposition"].get("validity"),
                e["disposition"].get("resolution"),
            )

        result = self._mutate(mutate)
        self.assertTrue(any("future" in e for e in result.errors), result.errors)

    def test_human_false_positive_requires_ldap(self):
        def mutate(l):
            l["events"][0]["source"]["actor"]["ldap_verified"] = False

        result = self._mutate(mutate)
        self.assertTrue(any("verified identity" in e for e in result.errors), result.errors)

    def test_severity_override_human_only(self):
        def mutate(l):
            l["events"][0]["disposition"] = {"severity": "high"}
            l["events"][0]["source"]["actor"] = {"kind": "machine", "identity": "triage/0.27.0"}
            l["events"][0]["event_id"] = compute_event_id(
                l["events"][0]["source"]["ref"], l["events"][0]["finding_ref"], None, None
            )

        result = self._mutate(mutate)
        self.assertTrue(any("human-only" in e for e in result.errors), result.errors)

    def test_severity_override_valid_human_event_passes(self):
        layer = copy.deepcopy(_valid_layer())
        layer["events"][0]["disposition"] = {"severity": "critical"}
        layer["events"][0]["event_id"] = compute_event_id(
            layer["events"][0]["source"]["ref"], layer["events"][0]["finding_ref"], None, None
        )
        self.assertEqual(_layer_schema_errors(layer), [])
        result = _layer_cross(layer)
        self.assertFalse(any("severity" in e for e in result.errors), result.errors)

    def test_severity_override_requires_rationale(self):
        def mutate(l):
            l["events"][0]["disposition"] = {"severity": "low"}
            l["events"][0]["rationale"] = ""
            l["events"][0]["event_id"] = compute_event_id(
                l["events"][0]["source"]["ref"], l["events"][0]["finding_ref"], None, None
            )

        result = self._mutate(mutate)
        self.assertTrue(any("requires a rationale" in e for e in result.errors), result.errors)

    def test_machine_false_positive_allowed_without_ldap(self):
        def mutate(l):
            l["events"][0]["source"]["actor"] = {"kind": "machine", "identity": "validate-findings"}
            l["events"][0]["source"]["type"] = "validation_report"

        result = self._mutate(mutate)
        self.assertFalse(any("verified identity" in e for e in result.errors), result.errors)

    def test_occurred_at_after_recorded_at_warns(self):
        def mutate(l):
            l["events"][0]["occurred_at"] = "2026-07-09T10:00:00+00:00"

        result = self._mutate(mutate)
        self.assertTrue(any("occurred_at" in w for w in result.warnings), result.warnings)

    def test_occurred_at_before_recorded_at_ok(self):
        def mutate(l):
            l["events"][0]["occurred_at"] = "2026-06-20T10:00:00+00:00"

        result = self._mutate(mutate)
        self.assertFalse(any("occurred_at" in w for w in result.warnings), result.warnings)
        self.assertEqual(result.errors, [])

    def test_confirmed_review_item_needs_matching_event(self):
        def mutate(l):
            l["needs_review"][0]["status"] = "confirmed"

        result = self._mutate(mutate)
        self.assertTrue(
            any("no event references source_ref" in e for e in result.errors), result.errors
        )


class TestDispositionCrossChecks(unittest.TestCase):
    """Cumulative-report disposition consistency (base report schema)."""

    def _cumulative(self):
        r = _consistency_report()
        for f in r["findings"]:
            f["disposition"] = {
                "validity": f["validation_status"],
                "resolution": "open",
                "last_updated": "2026-07-10T12:00:00+00:00",
                "events": [],
            }
        r["disposition_summary"] = {
            "layer_ref": "test-widget-findings-layer.json",
            "generated_at": "2026-07-10T12:00:00+00:00",
            "by_resolution": {
                "open": 2,
                "fix_in_progress": 0,
                "resolved": 0,
                "partially_resolved": 0,
                "risk_accepted": 0,
                "regression_introduced": 0,
            },
            "by_validity": {
                "confirmed": 0,
                "corrected": 0,
                "false_positive": 0,
                "not_verified": 2,
            },
            "conflicts": [],
            "needs_review_count": 0,
        }
        return r

    def _mutate(self, fn):
        r = self._cumulative()
        fn(r)
        return _cross_errors(r)

    def test_valid_cumulative_passes(self):
        r = self._cumulative()
        self.assertEqual(_schema_errors(r), [])
        self.assertEqual(_cross_errors(r).errors, [])

    def test_validation_status_disposition_mismatch(self):
        result = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "confirmed")
        )
        self.assertTrue(any("does not equal" in e for e in result.errors), result.errors)

    def test_resolution_count_mismatch(self):
        result = self._mutate(
            lambda r: r["disposition_summary"]["by_resolution"].__setitem__("resolved", 2)
        )
        self.assertTrue(any("by_resolution[resolved]" in e for e in result.errors), result.errors)

    def test_missing_disposition_on_one_finding(self):
        result = self._mutate(lambda r: r["findings"][1].pop("disposition"))
        self.assertTrue(any("no disposition block" in e for e in result.errors), result.errors)

    def test_conflict_flag_summary_mismatch(self):
        result = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("conflict", True)
        )
        self.assertTrue(
            any("disposition_summary.conflicts" in e for e in result.errors), result.errors
        )

    def test_audit_report_without_dispositions_unaffected(self):
        result = _cross_errors(_consistency_report())
        self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()


class TestFindingIdentityStamp:
    """`fingerprint` is schema-declared but OPTIONAL, so an unstamped
    report validates clean while being invisible to cross-scan
    continuation, disposition carry-forward, and the downstream
    platform's identity model. The validator errors on the gap by
    default — --strict does not re-report it.

    Presence is not the property that matters. The schema pattern
    constrains shape only, so any 64 hex characters used to pass both the
    schema and this check — and under the 3D decision a downstream
    consumer reads that stamp as authoritative identity rather than
    computing its own. The recipe is deterministic, so the check
    recomputes it: ABSENT and MISMATCH are both errors, kept as
    distinct messages (P6 flip 2026-08-13, once the corpus reached
    100% stamped — the backfill is a floor, not a snapshot).

    Measured 2026-08-11 over the full corpus: the overwhelming majority of
    findings carried a correct stamp, with a small absent tail and a smaller
    mismatched one concentrated in a few dozen files."""

    #: sentinel meaning "compute the fingerprint this finding should carry"
    AUTO = object()

    def _rep(self, *fps, repository=None):
        """Build a report. Each fp is None (unstamped), AUTO (correctly
        stamped), or a literal string (stamped with that exact value)."""
        findings = []
        for i, fp in enumerate(fps, 1):
            f = {
                "id": f"X-abc1234-{i:03d}",
                "cwes": ["CWE-918"],
                "locations": [{"path": f"pkg/a{i}.go", "lines": "1-2"}],
            }
            if fp is self.AUTO:
                f["fingerprint"] = fingerprint(f, repository)
            elif fp:
                f["fingerprint"] = fp
            findings.append(f)
        rep = {"findings": findings}
        if repository:
            rep["metadata"] = {"repository": repository}
        return rep

    def _run(self, report, strict=False):
        res = ValidationResult("r.json")
        check_finding_identity(report, res)
        if strict:
            strict_checks(report, res)
        return res

    def test_all_stamped_is_silent(self):
        res = self._run(self._rep(self.AUTO, self.AUTO))
        assert not res.warnings and not res.errors

    def test_correct_stamps_survive_a_repository_value(self):
        res = self._run(self._rep(self.AUTO, self.AUTO, repository="https://github.com/org/repo"))
        assert not res.warnings and not res.errors

    def test_missing_stamp_errors_and_names_the_fix(self):
        """P6 flip 2026-08-13: absent was a warning while the corpus still had
        unstamped findings. Coverage is 100% and enforced, so it is now a hard
        failure — otherwise the backfill was a snapshot, not a floor."""
        res = self._run(self._rep(self.AUTO, None))
        assert len(res.errors) == 1
        e = res.errors[0]
        assert "1 of 2" in e
        # Assert the tool and subcommand, not the invocation spelling: this
        # pinned "finding_identity.py fingerprint" and broke when
        # traust-engine 0.7.1 moved to the `python3 -m` module form that
        # AGENTS.md mandates for package modules. What the message owes the
        # reader is a runnable fix, not one particular way of spelling it.
        assert "finding_identity fingerprint" in e, "must name the fix"
        assert "--write" in e, "the named fix must be runnable"

    def test_fabricated_stamp_is_an_error(self):
        """The regression this check exists for: 64 well-formed hex
        characters that the recipe never produced must not pass."""
        res = self._run(self._rep("a" * 64, self.AUTO))
        assert len(res.errors) == 1, "a fabricated stamp must not be silent"
        e = res.errors[0]
        assert "1 of 2" in e
        assert "recipe does not produce" in e
        assert "X-abc1234-001" in e, "must name the offending finding"

    def test_single_character_tamper_is_caught(self):
        r = self._rep(self.AUTO)
        fp = r["findings"][0]["fingerprint"]
        r["findings"][0]["fingerprint"] = ("b" if fp[0] != "b" else "c") + fp[1:]
        assert len(self._run(r).errors) == 1

    def test_absent_and_mismatched_are_reported_separately(self):
        """Both are errors now, but they must stay DISTINCT messages: "you never
        stamped" and "your stamp is forged" need different fixes."""
        res = self._run(self._rep(None, "a" * 64, self.AUTO))
        assert len(res.errors) == 2, res.errors
        assert any("have no cross-scan" in e and "1 of 3" in e for e in res.errors)
        assert any("recipe does not produce" in e and "1 of 3" in e for e in res.errors)

    def test_mismatch_error_truncates_the_id_list(self):
        res = self._run(self._rep(*(["a" * 64] * 9)))
        assert "..." in res.errors[0]
        assert "9 of 9" in res.errors[0]

    def test_repository_change_after_stamping_is_a_mismatch(self):
        """Re-pointing metadata.repository silently re-identifies every
        finding — the check catches it because repo is the first field of
        the payload."""
        r = self._rep(self.AUTO, repository="https://github.com/org/repo")
        r["metadata"]["repository"] = "https://github.com/org/other"
        assert len(self._run(r).errors) == 1

    def test_no_findings_is_silent(self):
        assert not self._run({"findings": []}).warnings
        assert not self._run({}).warnings

    def test_absent_error_truncates_the_id_list(self):
        res = self._run(self._rep(*([None] * 9)))
        assert "..." in res.errors[0]
        assert "9 of 9" in res.errors[0]

    def test_strict_does_not_duplicate_the_identity_error(self):
        """Was test_strict_makes_it_an_error, which asserted strict mode
        promoted an absent stamp from warning to error. After the P6 flip the
        default path already ERRORS (see above), so traust-engine 0.7.1
        removed the strict re-scan rather than report one defect twice. The
        no-double-reporting contract is what is worth pinning now."""
        res = ValidationResult("r.json")
        strict_checks(self._rep(None, self.AUTO), res)
        assert not [e for e in res.errors if "fingerprint" in e], res.errors

    def test_strict_silent_when_all_stamped(self):
        res = ValidationResult("r.json")
        strict_checks(self._rep(self.AUTO), res)
        assert not [e for e in res.errors if "fingerprint" in e]
