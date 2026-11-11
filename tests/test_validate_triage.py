#!/usr/bin/env python3
"""Unit tests for schema/triage.schema.json."""

import unittest

from traust_core.v1.contracts import schema_errors


def _finding(**kw):
    base = {
        "id": "f001",
        "orig_id": "TEST_REPO-abc1234-001",
        "title": "Cross-tenant token theft via scope gap",
        "file": "pkg/rbac/scope.go",
        "line": 37,
        "category": "authorization",
        "claimed_severity": "critical",
        "verdict": "true_positive",
        "verify_verdict": "exploitable",
        "confidence": 9.0,
        "severity": "critical",
        "rationale": "reachable at handler.go:73; no ownership check",
        "vote_breakdown": {
            "true_positive": 3,
            "hardening": 0,
            "false_positive": 0,
            "cannot_verify": 0,
        },
        "refute_reasons": [],
        "exclusion_rule": None,
        "first_links": ["plugins/credentials/plugin.go:73"],
        "duplicate_of": None,
        "owner_hint": "@maintainers (CODEOWNERS)",
    }
    base.update(kw)
    return base


def _valid_triage():
    return {
        "triage_completed": "2026-07-09",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant internet-facing platform",
            "votes_per_finding": 3,
            "repo": "/tmp/clone",
            "harness_version": "0.24.0-e240e87",
        },
        "summary": {
            "input_count": 3,
            "true_positives": 1,
            "hardening": 1,
            "false_positives": 1,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            _finding(),
            _finding(
                id="f002",
                orig_id="TEST_REPO-abc1234-002",
                title="CORS wildcard on public API",
                verdict="hardening",
                verify_verdict="hardening",
                severity=None,
                exclusion_rule="13",
                confidence=8.0,
                vote_breakdown={
                    "true_positive": 0,
                    "hardening": 3,
                    "false_positive": 0,
                    "cannot_verify": 0,
                },
            ),
            _finding(
                id="f003",
                orig_id="TEST_REPO-abc1234-003",
                title="Dev-overlay default credentials",
                verdict="false_positive",
                verify_verdict="refuted",
                severity=None,
                exclusion_rule="2",
                confidence=8.0,
                refute_reasons=["intentional_behavior"],
                vote_breakdown={
                    "true_positive": 0,
                    "hardening": 0,
                    "false_positive": 3,
                    "cannot_verify": 0,
                },
                owner_hint=None,
            ),
        ],
    }


def _schema_errors(doc):
    return [m for _, m in schema_errors("triage", doc)]


class TestTriageSchema(unittest.TestCase):
    def test_valid_document_passes(self):
        self.assertEqual(_schema_errors(_valid_triage()), [])

    def test_verdict_enum_rejects_unknown(self):
        doc = _valid_triage()
        doc["findings"][0]["verdict"] = "probably_fine"
        self.assertTrue(_schema_errors(doc))

    def test_harness_version_required(self):
        doc = _valid_triage()
        del doc["triage_context"]["harness_version"]
        self.assertTrue(any("harness_version" in e for e in _schema_errors(doc)))

    def test_severity_vocabulary_matches_report_schema(self):
        doc = _valid_triage()
        doc["findings"][0]["severity"] = "HIGH"  # uppercase rejected
        self.assertTrue(_schema_errors(doc))

    def test_vote_breakdown_requires_hardening_key(self):
        doc = _valid_triage()
        del doc["findings"][0]["vote_breakdown"]["hardening"]
        # rejected via the anyOf wrapper, so assert rejection rather than
        # a specific message
        self.assertTrue(_schema_errors(doc))

    def test_unknown_finding_field_rejected(self):
        doc = _valid_triage()
        doc["findings"][0]["novel_field"] = 1
        self.assertTrue(_schema_errors(doc))

    def test_recommendation_carried_through_accepted(self):
        doc = _valid_triage()
        doc["findings"][0]["recommendation"] = "Add an ownership check before issuing the token."
        self.assertEqual(_schema_errors(doc), [])

    def test_recommendation_null_accepted(self):
        doc = _valid_triage()
        doc["findings"][0]["recommendation"] = None
        self.assertEqual(_schema_errors(doc), [])


if __name__ == "__main__":
    unittest.main()
