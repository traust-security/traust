#!/usr/bin/env python3
"""Tests for the optional per-finding isolation tags (PEACH lens
Phase 2): isolation_dimensions / isolation_boundary on secure-code-audit and
cloud-config-audit findings, vocabulary shared with isolation-review."""

import json
import unittest
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parent.parent

DIMENSIONS = ["privilege", "encryption", "authentication", "connectivity", "hygiene"]


def _load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def _load_schema(name):
    from traust.paths import schema_path as _sp

    return json.loads(_sp(name).read_text(encoding="utf-8"))


def _errors(schema, doc):
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [e.message for e in validator.iter_errors(doc)]


def _report():
    """Minimal report that passes schema/report.schema.json."""
    return {
        "title": "Security Assessment — Isolation Tag Test",
        "metadata": {
            "date": "2026-07-20",
            "scope": "First-party Go source, Kubernetes manifests",
        },
        "executive_summary": {
            "prose": (
                "One finding on the shared query endpoint of a multi-tenant "
                "controller; the boundary between tenants is data-scoped only."
            ),
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {
                "level": "critical",
                "definition": "Remote attacker reaches every tenant's data unauthenticated.",
            },
            {"level": "high", "definition": "Authenticated tenant reads another tenant's objects."},
            {
                "level": "medium",
                "definition": "Requires elevated prerequisites or enables denial of service.",
            },
            {"level": "low", "definition": "Hardening gap with no direct exploitability."},
        ],
        "findings": [
            {
                "id": "TEST-001",
                "title": "Cluster-wide List without tenant scoping",
                "severity": "high",
                "cwes": ["CWE-863"],
                "locations": [{"path": "pkg/query/handler.go", "lines": "10-40"}],
                "description": (
                    "The query handler lists objects cluster-wide under the "
                    "controller identity and filters by tenant only after the read."
                ),
                "remediation": "Scope List calls to the calling tenant's namespace before the query.",
            },
        ],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 1, "finding_ids": ["TEST-001"]},
            {"severity": "medium", "count": 0, "finding_ids": []},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "P0",
                "action": "Scope List calls to the calling tenant's namespace",
                "addresses": ["TEST-001"],
            },
        ],
    }


def _cca_report():
    """Minimal report that passes schema/cloud-config-audit.schema.json."""
    return {
        "title": "Cloud Config Audit — Isolation Tag Test",
        "metadata": {
            "target": "test-iac",
            "assessment_mode": "declared",
            "harness_version": "0.120.0-abc1234",
            "checkov_version": "3.2.0",
            "facts_ref": "test-iac-cloud-facts.json",
            "facts_snapshot_id": "0123456789abcdef",
            "deterministic_steps": [
                {"tool": "checkov", "invocation": "run_checkov.py --target-dir ."},
            ],
        },
        "summary": {
            "facts_total": 1,
            "confirmed": 1,
            "suppressed": 0,
            "needs_review": 0,
            "gaps": 0,
        },
        "findings": [
            {
                "id": "CCA-test-iac-001",
                "fact_ids": ["cca-0123456789ab"],
                "framework": "kubernetes",
                "provider": "kubernetes",
                "check_id": "CKV_K8S_TEST",
                "title": "No default-deny NetworkPolicy for tenant namespaces",
                "severity": "high",
                "status": "confirmed",
                "rationale": "R1 exposure: tenant-reachable path without default-deny.",
            },
        ],
    }


class TestReportSchemaIsolationTags(unittest.TestCase):
    SCHEMA = _load_schema("report")

    def test_finding_without_isolation_fields_stays_valid(self):
        self.assertEqual(_errors(self.SCHEMA, _report()), [])

    def test_finding_with_isolation_fields_validates(self):
        r = _report()
        r["findings"][0]["isolation_dimensions"] = ["privilege", "connectivity"]
        r["findings"][0]["isolation_boundary"] = "tenant query endpoint"
        self.assertEqual(_errors(self.SCHEMA, r), [])

    def test_every_dimension_value_accepted(self):
        r = _report()
        r["findings"][0]["isolation_dimensions"] = list(DIMENSIONS)
        self.assertEqual(_errors(self.SCHEMA, r), [])

    def test_invalid_dimension_rejected(self):
        r = _report()
        r["findings"][0]["isolation_dimensions"] = ["network"]
        self.assertTrue(_errors(self.SCHEMA, r))

    def test_empty_dimensions_array_rejected(self):
        r = _report()
        r["findings"][0]["isolation_dimensions"] = []
        self.assertTrue(_errors(self.SCHEMA, r))

    def test_empty_boundary_rejected(self):
        r = _report()
        r["findings"][0]["isolation_dimensions"] = ["privilege"]
        r["findings"][0]["isolation_boundary"] = ""
        self.assertTrue(_errors(self.SCHEMA, r))

    def test_dimension_enum_matches_isolation_review_schema(self):
        """The per-finding vocabulary must stay identical to the five
        dimension keys owned by isolation-review (Phase 0)."""
        iso = _load_schema("isolation-review")
        owned = list(iso["definitions"]["interface"]["properties"]["dimensions"]["required"])
        tagged = self.SCHEMA["$defs"]["finding"]["properties"]["isolation_dimensions"]["items"][
            "enum"
        ]
        self.assertEqual(tagged, owned)


class TestCloudConfigSchemaIsolationTags(unittest.TestCase):
    SCHEMA = _load_schema("cloud-config-audit")

    def test_finding_without_isolation_fields_stays_valid(self):
        self.assertEqual(_errors(self.SCHEMA, _cca_report()), [])

    def test_finding_with_isolation_fields_validates(self):
        r = _cca_report()
        r["findings"][0]["isolation_dimensions"] = ["connectivity"]
        r["findings"][0]["isolation_boundary"] = "tenant namespace network path"
        self.assertEqual(_errors(self.SCHEMA, r), [])

    def test_invalid_dimension_rejected(self):
        r = _cca_report()
        r["findings"][0]["isolation_dimensions"] = ["segmentation"]
        self.assertTrue(_errors(self.SCHEMA, r))

    def test_dimension_enum_matches_report_schema(self):
        report_schema = _load_schema("report")
        self.assertEqual(
            self.SCHEMA["properties"]["findings"]["items"]["properties"]["isolation_dimensions"][
                "items"
            ]["enum"],
            report_schema["$defs"]["finding"]["properties"]["isolation_dimensions"]["items"][
                "enum"
            ],
        )


if __name__ == "__main__":
    unittest.main()
