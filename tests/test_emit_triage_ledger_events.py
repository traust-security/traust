#!/usr/bin/env python3
"""Unit tests for traust.cli.emit_triage_ledger_events — the triage-report
→ disposition-ledger emitter."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traust_engine.ledger.service import SubmitResult

from traust.cli.emit_triage_ledger_events import main
from traust.cli.emit_validation_ledger_events import merge_register

RECORDED = "2026-07-13T12:00:00+00:00"


class _MockLedgerService:
    """File-only LedgerService stand-in that needs no LAAS_TOKEN."""

    def __init__(self, client=None, *, data_dir=None):
        pass

    def ensure_layer_file(self, layer_path, *, shell=None):
        if not layer_path.exists():
            layer_path.parent.mkdir(parents=True, exist_ok=True)
            layer_path.write_text(json.dumps(shell or {"events": [], "metadata": {}}) + "\n")
        return json.loads(layer_path.read_text(encoding="utf-8"))

    def submit_events(self, layer_path, events, *, report_path=None, queue_items=None):
        layer = json.loads(layer_path.read_text(encoding="utf-8"))
        existing = {e.get("event_id") for e in layer.get("events", [])}
        new = [e for e in events if e.get("event_id", id(e)) not in existing]
        layer.setdefault("events", []).extend(new)
        layer_path.write_text(json.dumps(layer, indent=2) + "\n")
        return SubmitResult(
            event_ids=[str(i) for i in range(len(new))], queue_added=len(queue_items or [])
        )


def _audit():
    return {
        "metadata": {
            "repository": "https://example.invalid/repoX",
            "commit": "abc1234",
            "date": "2026-07-01",
        },
        "findings": [
            {
                "id": "FIND-001",
                "title": "Unsanitized path join",
                "severity": "low",
                "cwes": ["CWE-22"],
                "locations": ["pkg/reg.go:42"],
                "description": "A path traversal.",
                "remediation": "Sanitize.",
            }
        ],
    }


def _triage():
    return {
        "title": "repoX triage",
        "triage_completed": RECORDED,
        "metadata": {"harness_version": "0.6.5-1234abc"},
        "findings": [
            {
                "id": "FIND-001",
                "verdict": "false_positive",
                "rationale": "guard exists at handler.go:47",
                "confidence": 5,
                "claimed_severity": "low",
                "refute_reasons": ["guard exists"],
            }
        ],
        "summary": {},
    }


class TestRefutedRegister(unittest.TestCase):
    def test_triage_emitter_preserves_validation_register_entries(self):
        """The validation emitter merge-appends into the same refuted
        register (merge_register: "never clobber another source's entries");
        a triage emission must not delete those entries."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit_path = root / "repoX-security-audit.json"
            audit_path.write_text(json.dumps(_audit()))
            triage_path = root / "repoX-triage.json"
            triage_path.write_text(json.dumps(_triage()))
            weights = root / "weights.json"
            weights.write_text(json.dumps({"version": "0"}))
            layer_path = root / "repoX-findings-layer.json"
            register_path = root / "repoX-refuted-register.json"

            # A prior validation run merge-appended its refuted entry.
            merge_register(
                register_path,
                "validations/repoX/v.json",
                [
                    {
                        "finding_ref": "FIND-001",
                        "asserted_by": "validate-findings/0.6.5",
                        "tier": "countersign",
                        "refute_reasons": ["execution refuted the claim"],
                    }
                ],
                RECORDED,
            )
            assert register_path.is_file()

            with (
                patch("traust.cli.emit_triage_ledger_events.load_engine", return_value=None),
                patch("traust.cli.emit_triage_ledger_events.bind_ledger"),
                patch("traust.cli.emit_triage_ledger_events.LedgerService", _MockLedgerService),
            ):
                rc = main(
                    [
                        str(triage_path),
                        "--audit",
                        str(audit_path),
                        "--layer",
                        str(layer_path),
                        "--weights",
                        str(weights),
                        "--findings-root",
                        str(root),
                        "--recorded-at",
                        RECORDED,
                    ]
                )
            self.assertEqual(rc, 0, "triage emitter main() must succeed")

            doc = json.loads(register_path.read_text(encoding="utf-8"))
            asserted_by = {e.get("asserted_by") for e in doc.get("entries", [])}
            self.assertIn(
                "validate-findings/0.6.5",
                asserted_by,
                f"validation-source register entries were clobbered: {doc}",
            )
            self.assertIn("validations/repoX/v.json", doc.get("sources", []))


if __name__ == "__main__":
    unittest.main()
