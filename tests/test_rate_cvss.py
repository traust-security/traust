"""`traust reporting rate-cvss`: fill findings' CVSS scores and severities
from their vectors with the CVSS calculator, so an author never scores or
bands a vector by hand."""

import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from traust.cli.groups.reporting import call_rate_cvss

LOW_LABELLED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"  # computes 4.2, medium
V4_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"  # 9.3


def report(*findings):
    return {"metadata": {"audit_profile": "code"}, "findings": list(findings)}


class TestRateCvss(unittest.TestCase):
    def test_a_moved_band_is_recounted_in_both_summaries(self):
        document = report(
            {"id": "A-1", "severity": "low", "cvss": {"vector": LOW_LABELLED, "score": 3.1}}
        )
        document["executive_summary"] = {
            "prose": "x",
            "severity_counts": {
                s: 0 for s in ("critical", "high", "medium", "low", "informational")
            }
            | {"low": 1},
        }
        document["findings_summary"] = [
            {
                "severity": s,
                "count": 1 if s == "low" else 0,
                "finding_ids": ["A-1"] if s == "low" else [],
            }
            for s in ("critical", "high", "medium", "low")
        ]
        rc, out = self._run(document)
        self.assertEqual(rc, 0)
        counts = out["executive_summary"]["severity_counts"]
        self.assertEqual((counts["medium"], counts["low"]), (1, 0))
        by = {e["severity"]: e for e in out["findings_summary"]}
        self.assertEqual(by["medium"]["finding_ids"], ["A-1"])
        self.assertEqual(by["low"], {"severity": "low", "count": 0, "finding_ids": []})

    def test_a_missing_or_malformed_report_is_a_controlled_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent.json"
            self.assertEqual(call_rate_cvss(Namespace(report=missing, vector=None, check=False)), 1)
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            self.assertEqual(call_rate_cvss(Namespace(report=bad, vector=None, check=False)), 1)
            self.assertEqual(bad.read_text(encoding="utf-8"), "{not json")

    def _run(self, document, check=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x-security-audit.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            rc = call_rate_cvss(Namespace(report=path, vector=None, check=check))
            return rc, json.loads(path.read_text(encoding="utf-8"))

    def test_label_below_its_vector_is_set_to_the_calculators_band(self):
        finding = {"id": "A-1", "severity": "low", "cvss": {"vector": LOW_LABELLED, "score": 3.1}}
        rc, out = self._run(report(finding))
        self.assertEqual(rc, 0)
        self.assertEqual(out["findings"][0]["cvss"], {"vector": LOW_LABELLED, "score": 4.2})
        self.assertEqual(out["findings"][0]["severity"], "medium")

    def test_cvss_4_vector_is_scored(self):
        rc, out = self._run(
            report({"id": "A-2", "severity": "high", "cvss": {"vector": V4_CRITICAL}})
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out["findings"][0]["cvss"]["score"], 9.3)
        self.assertEqual(out["findings"][0]["severity"], "critical")

    def test_findings_without_a_vector_are_left_alone(self):
        untouched = {"id": "A-3", "severity": "informational"}
        rc, out = self._run(report(untouched))
        self.assertEqual(rc, 0)
        self.assertEqual(out["findings"][0], untouched)

    def test_check_reports_disagreement_without_writing(self):
        finding = {"id": "A-1", "severity": "low", "cvss": {"vector": LOW_LABELLED, "score": 3.1}}
        rc, out = self._run(report(finding), check=True)
        self.assertEqual(rc, 1)
        self.assertEqual(out["findings"][0]["severity"], "low")

    def test_check_passes_when_score_and_band_match(self):
        finding = {
            "id": "A-1",
            "severity": "medium",
            "cvss": {"vector": LOW_LABELLED, "score": 4.2},
        }
        rc, _ = self._run(report(finding), check=True)
        self.assertEqual(rc, 0)

    def test_unscorable_vector_writes_nothing(self):
        good = {"id": "A-1", "severity": "low", "cvss": {"vector": LOW_LABELLED, "score": 3.1}}
        bad = {"id": "A-2", "severity": "high", "cvss": {"vector": "CVSS:3.1/AV:X"}}
        rc, out = self._run(report(good, bad))
        self.assertEqual(rc, 1)
        self.assertEqual(out["findings"][0]["severity"], "low")

    def test_single_vector_mode_prints_score_and_band(self):
        buf = StringIO()
        with redirect_stdout(buf):
            rc = call_rate_cvss(Namespace(report=None, vector=LOW_LABELLED, check=False))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
