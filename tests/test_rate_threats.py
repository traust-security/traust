"""`traust reporting rate-threats`: fill OWASP ratings' derived values from
their factors, so an author never does the arithmetic by hand."""

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from traust.cli.groups.reporting import call_rate_threats

FACTORS_ONLY = {
    "method": "owasp-risk-rating",
    "likelihood": {
        "factors": {
            "skill_level": 5,
            "motive": 2,
            "opportunity": 7,
            "population_size": 1,
            "ease_of_discovery": 3,
            "ease_of_exploit": 6,
            "awareness": 9,
            "intrusion_detection": 2,
        }
    },
    "impact": {
        "basis": "technical",
        "technical": {"confidentiality": 9, "integrity": 7, "availability": 5, "accountability": 8},
    },
    "rationale": {"awareness": "public"},
}


def model(*ratings):
    threats = [{"id": f"T{i}", "risk_rating": r} for i, r in enumerate(ratings, 1)]
    threats.append({"id": "T9", "impact": "high", "likelihood": "likely"})  # legacy, untouched
    return {"system": "x", "threats": threats}


class TestRateThreats(unittest.TestCase):
    def _run(self, document, check=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x-threat-model.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            rc = call_rate_threats(Namespace(model=path, check=check))
            return rc, json.loads(path.read_text(encoding="utf-8"))

    def test_fills_scores_levels_and_severity_from_factors(self):
        rc, out = self._run(model(json.loads(json.dumps(FACTORS_ONLY))))
        self.assertEqual(rc, 0)
        rating = out["threats"][0]["risk_rating"]
        self.assertEqual(rating["likelihood"]["score"], 4.375)
        self.assertEqual(rating["likelihood"]["level"], "medium")
        self.assertEqual(rating["impact"]["score"], 7.25)
        self.assertEqual(rating["severity"], "high")
        self.assertEqual(rating["rationale"], {"awareness": "public"})
        self.assertEqual(out["threats"][1], {"id": "T9", "impact": "high", "likelihood": "likely"})

    def test_check_reports_without_writing(self):
        document = model(json.loads(json.dumps(FACTORS_ONLY)))
        rc, out = self._run(document, check=True)
        self.assertEqual(rc, 1)
        self.assertEqual(out, document)

    def test_a_bad_factor_writes_nothing(self):
        bad = json.loads(json.dumps(FACTORS_ONLY))
        bad["likelihood"]["factors"]["motive"] = 12
        document = model(json.loads(json.dumps(FACTORS_ONLY)), bad)
        rc, out = self._run(document)
        self.assertEqual(rc, 1)
        self.assertEqual(out, document)


if __name__ == "__main__":
    unittest.main()
