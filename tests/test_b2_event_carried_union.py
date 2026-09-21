#!/usr/bin/env python3
"""B2 — build_cumulative unions event-carried findings with the baseline's.

Only /secure-code-audit, /secure-rpm-audit and /secure-container-audit may write
an audit baseline (gate A15). A finding discovered between audits therefore rides
on its event in an `event.finding` block. Without the union those findings would
be recorded, signed, and invisible to every dashboard — the failure the ledger's
tenet 5 exists to prevent.
"""

from __future__ import annotations

import copy

from traust.cli.build_cumulative import build_cumulative

GENERATED_AT = "2026-08-17T12:00:00+00:00"
BASELINED = "TEST_WIDGET-abcdef0-001"
CARRIED = "TEST_WIDGET-8ff0742-900"


def _audit(findings=None):
    return {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-06-01",
            "commit": "abcdef0123456789abcdef0123456789abcdef01",
            "repository": "https://github.com/example/test-widget",
        },
        "findings": findings
        if findings is not None
        else [
            {
                "id": BASELINED,
                "title": "SSRF via webhook annotation",
                "severity": "high",
                "cwes": ["CWE-918"],
                "locations": [{"path": "pkg/hook/handler.go", "lines": "10-20"}],
                "description": "d",
                "remediation": "r",
                "validation_status": "not_verified",
            }
        ],
    }


def _claim(fid=CARRIED, severity="medium", title="Unvalidated redirect"):
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "cwes": ["CWE-601"],
        "locations": [{"path": "pkg/auth/callback.go", "lines": "88-94"}],
        "description": "d",
        "remediation": "r",
        "validation_status": "not_verified",
        "origin": "vuln-scan",
    }


def _arrival_event(finding=None, ref=None):
    """A producer's arrival event: resolution open, validity unstated."""
    fid = (finding or _claim())["id"]
    return {
        "event_id": "c" * 64,
        "finding_ref": ref or fid,
        "recorded_at": "2026-08-17T10:00:00+00:00",
        "source": {
            "type": "vuln_scan_report",
            "ref": "test-widget-vuln-findings.json",
            "actor": {"kind": "machine", "identity": "vuln-scan/0.282.0"},
        },
        "disposition": {"resolution": "open"},
        "rationale": "Discovered by a between-audit sweep.",
        "finding": finding or _claim(),
    }


def _layer(events=(), **meta):
    m = {
        "audit_report": "test-widget-security-audit.json",
        "repository": "https://github.com/example/test-widget",
        "created": "2026-06-01T00:00:00+00:00",
    }
    m.update(meta)
    return {"metadata": m, "events": list(events), "needs_review": []}


def _ids(report):
    return {f["id"] for f in report.get("findings", [])}


class TestUnion:
    def test_event_carried_finding_appears_in_the_report(self) -> None:
        rep = build_cumulative(_audit(), _layer([_arrival_event()]), "layer.json", GENERATED_AT)
        assert CARRIED in _ids(rep), "an event-carried finding must not be invisible (tenet 5)"

    def test_baseline_findings_still_appear(self) -> None:
        rep = build_cumulative(_audit(), _layer([_arrival_event()]), "layer.json", GENERATED_AT)
        assert BASELINED in _ids(rep)

    def test_no_events_means_baseline_only(self) -> None:
        """Existing layers must project exactly as before."""
        rep = build_cumulative(_audit(), _layer(), "layer.json", GENERATED_AT)
        assert _ids(rep) == {BASELINED}

    def test_carried_claim_fields_survive(self) -> None:
        rep = build_cumulative(_audit(), _layer([_arrival_event()]), "layer.json", GENERATED_AT)
        f = next(x for x in rep["findings"] if x["id"] == CARRIED)
        assert f["severity"] == "medium"
        assert f["cwes"] == ["CWE-601"]
        assert f["origin"] == "vuln-scan"


class TestPrecedence:
    def test_baseline_wins_over_event_carried_same_id(self) -> None:
        """Absorption at re-audit: once baselined, the baseline is authoritative.

        This is what lets a supplement be absorbed without a migration — the
        event stays in history, the baseline takes precedence from then on.
        """
        audit = _audit(
            [
                {
                    "id": CARRIED,
                    "title": "BASELINE VERSION",
                    "severity": "critical",
                    "cwes": ["CWE-601"],
                    "locations": [{"path": "pkg/auth/callback.go", "lines": "88-94"}],
                    "description": "d",
                    "remediation": "r",
                    "validation_status": "confirmed",
                }
            ]
        )
        rep = build_cumulative(audit, _layer([_arrival_event()]), "layer.json", GENERATED_AT)
        f = next(x for x in rep["findings"] if x["id"] == CARRIED)
        assert f["title"] == "BASELINE VERSION"
        assert f["severity"] == "critical", "the event-carried copy must not override the baseline"

    def test_later_arrival_supersedes_earlier(self) -> None:
        first = _arrival_event(_claim(severity="low", title="first observation"))
        second = copy.deepcopy(
            _arrival_event(_claim(severity="high", title="corrected observation"))
        )
        second["event_id"] = "d" * 64
        second["recorded_at"] = "2026-08-17T11:00:00+00:00"
        rep = build_cumulative(_audit(), _layer([first, second]), "layer.json", GENERATED_AT)
        f = next(x for x in rep["findings"] if x["id"] == CARRIED)
        assert f["title"] == "corrected observation"
        assert f["severity"] == "high"


class TestClaimPinning:
    def test_pinned_event_carried_claim_is_not_reported_missing(self) -> None:
        """The verifier must find it — it is present, just not in the baseline.

        Before B2 this reported "baselined finding missing from the audit
        report", which is the opposite of the truth.
        """
        from traust_engine.ledger import compute_claim_hash

        from traust.cli.build_cumulative import (
            verify_claim_hashes,
        )

        claim = _claim()
        layer = _layer(
            [_arrival_event(claim)], claim_hashes={claim["id"]: compute_claim_hash(claim)}
        )
        errors, _warnings = verify_claim_hashes(_audit(), layer)
        assert not any("missing from the audit report" in e for e in errors), errors

    def test_tampered_event_carried_claim_is_caught(self) -> None:
        from traust_engine.ledger import compute_claim_hash

        from traust.cli.build_cumulative import (
            verify_claim_hashes,
        )

        claim = _claim()
        pinned = compute_claim_hash(claim)
        tampered = {**claim, "severity": "low"}  # downgrade after pinning
        layer = _layer([_arrival_event(tampered)], claim_hashes={claim["id"]: pinned})
        errors, warnings = verify_claim_hashes(_audit(), layer)
        assert errors or warnings, "an edited event-carried claim must not verify clean"
