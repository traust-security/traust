#!/usr/bin/env python3
"""`traust triage check` and the triage skill's canary fixture."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path


def _report():
    return {
        "triage_completed": "2026-07-11",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant platform",
            "votes_per_finding": 3,
            "repo": "/tmp/clone",
            "harness_version": "0.26.0-abc1234",
        },
        "summary": {
            "input_count": 4,
            "true_positives": 1,
            "hardening": 1,
            "false_positives": 1,
            "undetermined": 1,
            "duplicates": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            {
                "id": "f001",
                "title": "Heap overflow in parse_alpha",
                "file": "entry.c",
                "line": 25,
                "category": "memory-safety",
                "claimed_severity": "HIGH",
                "verdict": "true_positive",
                "verify_verdict": "exploitable",
                "confidence": 9.0,
                "severity": "high",
                "owner_hint": "@team",
                "rationale": "reachable from main at entry.c:53; no bounds check",
                "first_links": ["entry.c:53"],
                "vote_breakdown": {
                    "true_positive": 3,
                    "hardening": 0,
                    "false_positive": 0,
                    "cannot_verify": 0,
                },
            },
            {
                "id": "f006",
                "title": "No securityContext in deployment",
                "file": "deploy/deployment.yaml",
                "line": 19,
                "category": "insecure-workload-config",
                "claimed_severity": "MEDIUM",
                "verdict": "hardening",
                "verify_verdict": "hardening",
                "confidence": 8.0,
                "severity": None,
                "exclusion_rule": "13",
                "owner_hint": "@team",
                "rationale": "accurate CIS gap at deploy/deployment.yaml:19; no exploit path.",
                "first_links": ["deploy/deployment.yaml:19"],
            },
            {
                "id": "f005",
                "title": "Null deref after fopen",
                "file": "entry.c",
                "line": 51,
                "category": "null-deref",
                "claimed_severity": "LOW",
                "verdict": "false_positive",
                "verify_verdict": "refuted",
                "confidence": 8.0,
                "severity": None,
                "exclusion_rule": "2",
                "refute_reasons": ["already_handled"],
                "rationale": "guard exists at entry.c:47 before the fread call.",
                "first_links": ["entry.c:47"],
            },
            {
                "id": "f007",
                "title": "Command injection in ghost renderer",
                "file": "src/ghost.go",
                "line": 42,
                "category": "injection",
                "claimed_severity": "HIGH",
                "verdict": "undetermined",
                "verify_verdict": "needs_manual_test",
                "confidence": 0,
                "severity": None,
                "refute_reasons": ["unlocatable"],
                "rationale": "cited material not found under --repo",
            },
        ],
    }


from traust.cli import triage_check
from traust.paths import skill_dir

FIXTURE_TARGET = skill_dir("triage") / "fixtures" / "canary-target"


class TestTriageCheck(unittest.TestCase):
    """`traust triage check`: the verdict-citation lint on traust-core (was lint_verdict_citations)."""

    def _check(self, findings=None, repo=FIXTURE_TARGET):
        report = _report()
        if findings is not None:
            report["findings"] = findings
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "repo-triage.json"
            path.write_text(json.dumps(report))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = triage_check.main([str(path), "--repo", str(repo), "--json"])
        return rc, json.loads(out.getvalue()) if rc == 0 else None

    def test_clean_verdicts_pass_against_fixture(self):
        self.assertEqual(self._check(), (0, []))

    def test_hallucinated_refutation_flagged_for_revote(self):
        findings = _report()["findings"]
        findings[2]["rationale"] = "guard exists at entry.c:9999 before use."
        findings[2]["first_links"] = ["lib/imaginary.c:12"]
        _, violations = self._check(findings)
        self.assertEqual({(v["item"], v["action"]) for v in violations}, {("f005", "re_vote")})
        messages = " ".join(v["message"] for v in violations)
        self.assertIn("out of range", messages)
        self.assertIn("not found", messages)

    def test_broken_tp_citation_is_review_not_revote(self):
        findings = _report()["findings"]
        findings[0]["first_links"] = ["lib/imaginary.c:12"]
        findings[0]["rationale"] = "reachable"
        _, violations = self._check(findings)
        self.assertEqual([(v["item"], v["action"]) for v in violations], [("f001", "review")])

    def test_duplicates_skipped(self):
        findings = _report()["findings"]
        findings[0].update(verdict="duplicate", duplicate_of="f005", first_links=["nope.c:1"])
        self.assertEqual(self._check(findings), (0, []))

    def test_an_invalid_triage_or_missing_repo_is_an_error(self):
        self.assertEqual(self._check(findings=[{"id": "x"}])[0], 2)
        self.assertEqual(self._check(repo=FIXTURE_TARGET / "absent")[0], 2)


class TestCanaryFixture(unittest.TestCase):
    """The self-contained smoke-test target must support every canary."""

    def test_planted_lines_match_fixture_citations(self):
        import json

        fixture = json.loads((FIXTURE_TARGET.parent / "canary-findings.json").read_text())
        entry = (FIXTURE_TARGET / "entry.c").read_text().splitlines()
        expect = {
            "f001": "memcpy(buf",
            "f002": "malloc(8)",
            "f003": "memcpy(local",
            "f004": "fread(buf",
            "f005": "fread(buf",
        }
        for f in fixture["findings"]:
            if f["id"] in expect:
                self.assertIn(
                    expect[f["id"]], entry[f["line"] - 1], f"{f['id']} cites line {f['line']}"
                )

    def test_hardening_canary_target_exists(self):
        self.assertTrue((FIXTURE_TARGET / "deploy" / "deployment.yaml").is_file())

    def test_undetermined_canary_target_absent(self):
        self.assertFalse((FIXTURE_TARGET / "src" / "ghost.go").exists())


if __name__ == "__main__":
    unittest.main()
