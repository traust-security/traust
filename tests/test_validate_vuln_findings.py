#!/usr/bin/env python3
"""Unit tests for schema/vuln-findings.schema.json."""

import unittest

from traust_core.v1.contracts import schema_errors


def _finding(**kw):
    base = {
        "id": "EXAMPLE_REPO-abc1234-001",
        "scanner_ref": "F-01-01",
        "file": "pkg/server/handler.go",
        "line": 73,
        "category": "command-injection",
        "cwe": "CWE-78",
        "severity": "high",
        "confidence": 0.9,
        "title": "Command injection via unsanitized template value",
        "description": (
            "The handler passes the request's template parameter into "
            "exec.Command without sanitization; untrusted input reaches the "
            "shell at handler.go:73."
        ),
        "exploit_scenario": "POST a template containing $(id) to /render.",
        "recommendation": "Use exec.Command with a fixed argv; never a shell string.",
        "confidence_reason": "Direct data flow from request to sink.",
    }
    base.update(kw)
    return base


def _valid_doc():
    return {
        "target": "targets/example-repo",
        "scanned_at": "2026-07-12T20:00:00Z",
        "focus_areas": ["HTTP handlers (pkg/server) — render, upload"],
        "metadata": {
            "repo": "example-repo",
            "repo_slug": "EXAMPLE_REPO",
            "scanned_ref": "abc1234",
            "harness_version": "0.38.0-de5a090",
            "baseline": "findings/example-repo/example-repo-security-audit.json",
            "baseline_findings": 12,
        },
        "findings": [_finding()],
        "known_findings": [
            {
                "title": "Path traversal in upload handler",
                "matches_baseline_id": "EXAMPLE_REPO-9cb7556-004",
            }
        ],
        "summary": {
            "total": 1,
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "known": 1,
            "low_confidence": 0,
        },
    }


def _schema_errors(doc):
    return [m for _, m in schema_errors("vuln-findings", doc)]


class TestVulnFindingsSchema(unittest.TestCase):
    def test_valid_document_passes(self):
        self.assertEqual(_schema_errors(_valid_doc()), [])

    def test_legacy_uppercase_severity_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["severity"] = "HIGH"
        self.assertTrue(_schema_errors(doc))

    def test_non_canonical_id_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["id"] = "F-001"
        self.assertTrue(_schema_errors(doc))

    def test_null_line_accepted(self):
        doc = _valid_doc()
        doc["findings"][0]["line"] = None
        self.assertEqual(_schema_errors(doc), [])

    def test_bad_cwe_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["cwe"] = "CWE78"
        self.assertTrue(_schema_errors(doc))

    def test_unknown_finding_field_rejected(self):
        doc = _valid_doc()
        doc["findings"][0]["novel_field"] = 1
        self.assertTrue(_schema_errors(doc))

    def test_empty_findings_valid(self):
        doc = _valid_doc()
        doc["findings"] = []
        doc["summary"].update(total=0, high=0)
        self.assertEqual(_schema_errors(doc), [])

    def test_non_git_scanned_ref_accepted(self):
        doc = _valid_doc()
        doc["metadata"]["scanned_ref"] = "0000000 (not a git checkout)"
        self.assertEqual(_schema_errors(doc), [])


if __name__ == "__main__":
    unittest.main()
