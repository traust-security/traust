from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from traust_core.v1.models.detection_quality import CheckPrecision, ComplianceCalibration
from traust_core.v1.models.vocabulary import ComplianceFramework

from traust.cli import compliance_precision
from traust.cli.groups import GROUPS


@pytest.mark.parametrize("assessments", [0, 2])
def test_precision_cli_exports_counts_gate_and_safe_human_view(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, assessments: int
) -> None:
    framework = next(iter(ComplianceFramework))
    calls = []

    def calibrate(value: ComplianceFramework, *, gate: float) -> ComplianceCalibration:
        calls.append((value, gate))
        return ComplianceCalibration(
            framework=value,
            assessments=assessments,
            gate=gate,
            checks=(CheckPrecision(check_id="tls<script>|x", fired=2, dismissed=1, gate=gate),)
            if assessments
            else (),
        )

    quality = SimpleNamespace(calibrate_compliance=calibrate)
    monkeypatch.setattr(
        compliance_precision,
        "load",
        lambda home: SimpleNamespace(services=lambda: SimpleNamespace(detection_quality=quality)),
    )
    rc = compliance_precision.main(
        [
            "--framework",
            framework.value,
            "--gate",
            "0.4",
            "--out-dir",
            str(tmp_path),
        ]
    )
    doc = json.loads((tmp_path / "compliance-precision.json").read_text())
    md = (tmp_path / "compliance-precision.md").read_text()
    assert rc == 0
    assert calls == [(framework, 0.4)]
    assert (doc["assessments"], doc["gate"]) == (assessments, 0.4)
    if assessments:
        assert (doc["checks"][0]["precision"], doc["checks"][0]["flagged"]) == (0.5, False)
        assert "<script>" not in md
        assert "&lt;script&gt;" in md
    else:
        assert doc["checks"] == []
        assert "unmeasured" in md


def test_field_precision_is_independently_routed_from_evaluator_calibration() -> None:
    spec = GROUPS["sweep"]["compliance-precision"]
    assert spec is not GROUPS["compliance"]["calibrate"]
