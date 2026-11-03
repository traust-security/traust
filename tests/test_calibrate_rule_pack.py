"""`traust impact calibrate-rule-pack`: the CLI layer only. The pack's name picks one of core's
rule packs, then one `DetectionQualityService.calibrate` over the given scans; a refused input is
exit 2. Scoring is traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.detection_quality import Calibration, GateReachability, RulePack
from traust_core.v1.models.rule_calibration import (
    CalibrationHit,
    CalibrationStatus,
    FixtureSanity,
    PackCalibrationRun,
    PackScan,
    RuleCalibrationRequest,
)

from traust.cli import calibrate_rule_pack

PACK = RulePack(name="crypto", version="1.9")
SCANS = [uuid.uuid4(), uuid.uuid4()]


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def stub(monkeypatch: pytest.MonkeyPatch, result: Any) -> Door:
    door = Door(result)
    services = SimpleNamespace(
        detection_quality=SimpleNamespace(rule_packs=lambda: [PACK], calibrate=door)
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = calibrate_rule_pack.main(["--config-home", str(home), *argv])
    return rc, out.getvalue() or err.getvalue()


def scans(*ids: uuid.UUID) -> list[str]:
    return [a for i in ids for a in ("--scan", str(i))]


def test_one_calibrate_of_the_named_pack_over_the_scans(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    result = Calibration(
        pack=PACK, scans=2, tp_files=3, reachability=GateReachability(repositories=1)
    )
    door = stub(monkeypatch, result)
    rc, out = run(home, "crypto", *scans(*SCANS))
    assert rc == 0
    assert door.calls == [(PACK, SCANS)]
    assert json.loads(out)["tp_files"] == 3


def test_an_unknown_pack_is_refused_before_core_scores(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    door = stub(monkeypatch, None)
    rc, err = run(home, "nope", *scans(SCANS[0]))
    assert rc == 2 and "rule pack 'nope'" in err and "crypto" in err
    assert door.calls == []


def test_a_refused_scan_is_exit_2_with_cores_reason(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    stub(monkeypatch, ValidationError("assessments x are not tool scans"))
    rc, err = run(home, "crypto", *scans(SCANS[0]))
    assert rc == 2 and "not tool scans" in err


def stub_live(monkeypatch: pytest.MonkeyPatch, result: Any) -> Door:
    door = Door(result)
    services = SimpleNamespace(detection_quality=SimpleNamespace(calibrate_pack=door))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


def test_fixture_mode_needs_no_recorded_scan_or_confirmed_corpus(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path
) -> None:
    result = PackCalibrationRun(
        pack=PACK,
        status=CalibrationStatus.COMPLETED,
        fixture=FixtureSanity(
            target=tmp_path / "pack" / "tests",
            scan=PackScan(
                files_scanned=1,
                engine_errors=0,
                skipped_rules=0,
                returncode=0,
                hits=(CalibrationHit(rule="demo", path="a.py", line=1, snippet="danger(x)"),),
            ),
        ),
    )
    door = stub_live(monkeypatch, result)
    output = tmp_path / "calibration"
    rc, text = run(
        home, "crypto", "--fixtures", "--rules", str(tmp_path / "pack"), "--out", str(output)
    )
    assert rc == 0 and json.loads(text)["fixture"]["scan"]["complete"]
    assert door.calls == [
        (RuleCalibrationRequest(pack="crypto", fixtures=True, rules=str(tmp_path / "pack")),)
    ]
    assert json.loads((output / "calibration.json").read_text())["status"] == "completed"
    assert json.loads((output / "review-samples.jsonl").read_text())["rule"] == "demo"
    assert "Rule-pack calibration" in (output / "summary.md").read_text()


def test_default_live_mode_uses_the_typed_core_workflow(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    door = stub_live(monkeypatch, PackCalibrationRun(pack=PACK, status=CalibrationStatus.COMPLETED))
    rc, _ = run(home, "crypto", "--limit", "3", "--timeout", "25")
    assert rc == 0
    assert door.calls == [(RuleCalibrationRequest(pack="crypto", limit=3, timeout=25),)]


@pytest.mark.parametrize("status", [CalibrationStatus.DEGRADED, CalibrationStatus.FAILED])
def test_an_incomplete_workflow_emits_evidence_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, home: Path, status: CalibrationStatus
) -> None:
    stub_live(monkeypatch, PackCalibrationRun(pack=PACK, status=status))
    rc, text = run(home, "crypto", "--fixtures")
    assert rc == 1 and json.loads(text)["status"] == status


def test_unavailable_fixtures_are_a_meaningful_refusal(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    stub_live(monkeypatch, ValidationError("no tests/ tree or annotated fixtures"))
    rc, text = run(home, "--fixtures")
    assert rc == 2 and "no tests/ tree" in text


def test_invalid_live_boundary_is_refused_before_core_is_called(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    door = stub_live(monkeypatch, None)
    rc, _ = run(home, "crypto", "--timeout", "0")
    assert rc == 2 and door.calls == []


def test_markdown_summary_keeps_untrusted_pack_text_inert(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path
) -> None:
    pack = PACK.model_copy(update={"name": "<script>alert(1)</script>"})
    stub_live(monkeypatch, PackCalibrationRun(pack=pack, status=CalibrationStatus.COMPLETED))
    rc, _ = run(home, "--fixtures", "--out", str(tmp_path / "out"))
    assert rc == 0
    assert "<script>" not in (tmp_path / "out" / "summary.md").read_text()
