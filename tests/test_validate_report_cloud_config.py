#!/usr/bin/env python3
"""Tests for schema/cloud-config-findings-current.schema.json (the cumulative shape
build_cumulative.py derives from a *-cloud-config-audit.json baseline), including the negative
direction: a code-audit cumulative report is not valid under it.
"""

import copy
import unittest

from traust_core.v1.contracts import schema_errors

GENERATED_AT = "2026-07-28T23:19:00+00:00"


def _valid_current():
    """Minimal cloud-config findings-current that passes all validation.

    Mirrors what build_cumulative.py emits over a cloud-config-audit
    baseline: audit finding core + disposition/validation_status/
    effective_severity per finding, disposition_summary, cumulative
    metadata stamp, title suffix."""
    return {
        "title": "Cloud config audit — widget (declared layer) — Cumulative Findings Status",
        "metadata": {
            "target": "widget",
            "assessment_mode": "declared",
            "target_head": "6cb81ba1a4077a2b812d6c8403d9f4f871a3d9f3",
            "ref": "main",
            "ref_kind": "default",
            "repository": "https://github.com/example/widget",
            "harness_version": "0.202.0",
            "checkov_version": "3.3.6",
            "facts_ref": "analysis-results/cloud-config/widget/widget-cloud-facts.json",
            "facts_snapshot_id": "b50717124734aae7",
            "generated_at": "2026-07-28T20:52:36Z",
            "frameworks": ["terraform"],
            "deterministic_steps": [
                {
                    "tool": "checkov (via run_checkov.py)",
                    "invocation": "python3 run_checkov.py --target-dir .",
                    "version": "3.3.6",
                }
            ],
            "additional": {
                "cumulative": {
                    "source_audit": "widget-cloud-config-audit.json",
                    "layer": "widget-findings-layer.json",
                    "original_report_date": None,
                    "generated_at": GENERATED_AT,
                }
            },
            "date": "2026-07-28",
        },
        "summary": {
            "facts_total": 2,
            "confirmed": 1,
            "suppressed": 1,
            "needs_review": 0,
            "gaps": 0,
            "by_severity": {"low": 1, "informational": 1},
            "by_provider": {"aws": 2},
        },
        "findings": [
            {
                "id": "CCA-widget-001",
                "fact_ids": ["cca-d0055ddb7a4a"],
                "framework": "terraform",
                "provider": "aws",
                "check_id": "CKV_AWS_1",
                "title": "S3 bucket lacks server-side encryption",
                "severity": "low",
                "scanner_severity": "unrated",
                "status": "confirmed",
                "rationale": "Rubric row R4: hygiene gap on a non-sensitive artifact bucket.",
                "locations": [
                    {
                        "file_path": "/main.tf",
                        "resource": "aws_s3_bucket.artifacts",
                        "file_line_range": [10, 24],
                    }
                ],
                "cwe": "CWE-311",
                "control_refs": [],
                "remediation": "Enable SSE-S3 on the bucket.",
                "disposition": {
                    "validity": "not_verified",
                    "resolution": "open",
                    "assurance": "claimed",
                    "last_updated": GENERATED_AT,
                    "events": [],
                },
                "validation_status": "not_verified",
                "effective_severity": "low",
            },
            {
                "id": "CCA-widget-002",
                "fact_ids": ["cca-f049540e9baa"],
                "framework": "terraform",
                "provider": "aws",
                "check_id": "CKV_AWS_2",
                "title": "Bucket versioning disabled",
                "severity": "informational",
                "scanner_severity": "unrated",
                "status": "suppressed",
                "rationale": "Versioning is handled by the backup pipeline; "
                "cited in docs/backup.md.",
                "locations": [
                    {
                        "file_path": "/main.tf",
                        "resource": "aws_s3_bucket.artifacts",
                        "file_line_range": [10, 24],
                    }
                ],
                "cwe": None,
                "control_refs": [],
                "remediation": None,
                "disposition": {
                    "validity": "not_verified",
                    "resolution": "open",
                    "assurance": "claimed",
                    "last_updated": GENERATED_AT,
                    "events": [],
                },
                "validation_status": "not_verified",
                "effective_severity": "informational",
            },
        ],
        "gaps": [],
        "disposition_summary": {
            "layer_ref": "widget-findings-layer.json",
            "generated_at": GENERATED_AT,
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
                "hardening": 0,
            },
            "severity_overrides": [],
            "conflicts": [],
            "needs_review_count": 0,
        },
    }


def _schema_errors(report):
    return [m for _, m in schema_errors("cloud-config-findings-current", report)]


# ---------------------------------------------------------------------------
# Good report
# ---------------------------------------------------------------------------


class TestValidCloudConfigCurrent(unittest.TestCase):
    def test_valid_current_passes_schema(self):
        self.assertEqual(_schema_errors(_valid_current()), [])


# ---------------------------------------------------------------------------
# Schema violations
# ---------------------------------------------------------------------------


class TestCloudConfigCurrentSchemaViolations(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_current())
        fn(r)
        return _schema_errors(r)

    def test_missing_disposition_summary(self):
        errors = self._mutate(lambda r: r.pop("disposition_summary"))
        self.assertTrue(
            any("'disposition_summary' is a required property" in e for e in errors), errors
        )

    def test_missing_finding_disposition(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("disposition"))
        self.assertTrue(any("'disposition' is a required property" in e for e in errors), errors)

    def test_missing_effective_severity(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("effective_severity"))
        self.assertTrue(
            any("'effective_severity' is a required property" in e for e in errors), errors
        )

    def test_title_without_cumulative_suffix(self):
        errors = self._mutate(
            lambda r: r.__setitem__("title", "Cloud config audit — widget (declared layer)")
        )
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_bad_finding_id_pattern(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("id", "WIDGET-abc-001"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_observed_assessment_mode_unrepresentable(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("assessment_mode", "observed"))
        self.assertTrue(any("declared" in e for e in errors), errors)

    def test_source_audit_must_reference_cloud_config_baseline(self):
        errors = self._mutate(
            lambda r: r["metadata"]["additional"]["cumulative"].__setitem__(
                "source_audit", "widget-security-audit.json"
            )
        )
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_invalid_disposition_validity(self):
        errors = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "maybe")
        )
        self.assertTrue(any("'maybe' is not one of" in e for e in errors), errors)

    def test_vintage_extras_tolerated(self):
        # Real corpus vintages carry campaign annotations and free-form
        # summary notes — the contract stays open there.
        def mutate(r):
            r["metadata"]["tracking"] = "PROJ-3528"
            r["metadata"]["campaign"] = "iac-baseline-sweep"
            r["summary"]["note"] = "DECLARED CONFIGURATION ONLY."

        self.assertEqual(self._mutate(mutate), [])

    def test_unknown_top_level_key_rejected(self):
        errors = self._mutate(lambda r: r.__setitem__("bogus", 1))
        self.assertTrue(any("additional properties" in e.lower() for e in errors), errors)


# ---------------------------------------------------------------------------
# Cross-validation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Auto-detection routing
# ---------------------------------------------------------------------------


def _code_audit_current():
    """A code-audit cumulative stub: report.schema.json-shaped stamp."""
    return {
        "title": "Security Assessment — Widget — Cumulative Findings Status",
        "metadata": {
            "date": "2026-07-28",
            "scope": "First-party Go source under cmd/ and pkg/.",
            "additional": {
                "cumulative": {
                    "source_audit": "widget-security-audit.json",
                    "layer": "widget-findings-layer.json",
                    "original_report_date": "2026-07-01",
                    "generated_at": GENERATED_AT,
                }
            },
        },
    }


class TestFindingsCurrentDetection(unittest.TestCase):
    def test_code_audit_current_fails_new_schema(self):
        # Negative: the code-audit cumulative shape is not valid under the
        # cloud-config-findings-current contract.
        self.assertTrue(_schema_errors(_code_audit_current()))


if __name__ == "__main__":
    unittest.main()
