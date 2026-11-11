#!/usr/bin/env python3
"""Unit tests for schema/report.schema.json and schema/verification.schema.json."""

import copy
import unittest

from traust_core.v1.contracts import schema_errors


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


def _canonical_report():
    report = _valid_report()
    for item, priority in zip(report["remediation_roadmap"], ("p0", "p1"), strict=True):
        item.update(priority=priority, effort=None)
    return report


def _schema_errors(report):
    return [m for _, m in schema_errors("report", report)]


# ---------------------------------------------------------------------------
# Good report
# ---------------------------------------------------------------------------


class TestValidReport(unittest.TestCase):
    def test_valid_report_passes_schema(self):
        errors = _schema_errors(_valid_report())
        self.assertEqual(errors, [])


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


# ---------------------------------------------------------------------------
# Directory validation (rglob)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Renderer smoke test
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 0.15.0 consistency conventions
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Remediation verification reports (verification.schema.json)
# ---------------------------------------------------------------------------


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
    return [m for _, m in schema_errors("verification", report)]


class TestVerificationSchema(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_verification_report())
        fn(r)
        return _verification_schema_errors(r)

    def test_valid_report_passes_schema(self):
        self.assertEqual(_verification_schema_errors(_valid_verification_report()), [])

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


# ---------------------------------------------------------------------------
# Findings disposition layers (layer.schema.json) and cumulative reports
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    unittest.main()
