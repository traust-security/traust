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
