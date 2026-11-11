"""`traust sweep screen-injection`: the CLI layer only. Each id is one
`DetectionQualityService.screen_injection`; any flagged report is exit 1, a refused id exit 2.
The screen is traust-core's."""

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
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.detection_quality import (
    InjectionScreen,
    InjectionSignal,
    InjectionSignalKind,
)

from traust.cli import recall

CLEAN, ECHO = uuid.uuid4(), uuid.uuid4()
SIGNAL = InjectionSignal(kind=InjectionSignalKind.INSTRUCTION_ECHO, detail="system directive")


class Screen:
    def __init__(self, refusal: Exception | None = None) -> None:
        self.calls: list[uuid.UUID] = []
        self.refusal = refusal

    def __call__(self, artifact_id: uuid.UUID) -> InjectionScreen:
        self.calls.append(artifact_id)
        if self.refusal is not None:
            raise self.refusal
        signals = (SIGNAL,) if artifact_id == ECHO else ()
        return InjectionScreen(artifact_id=artifact_id, signals=signals)


def stub(monkeypatch: pytest.MonkeyPatch, door: Screen) -> Screen:
    services = SimpleNamespace(detection_quality=SimpleNamespace(screen_injection=door))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(home: Path, *ids: object) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = recall.screen(["--config-home", str(home), *map(str, ids)])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_clean_reports_are_exit_0(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    door = stub(monkeypatch, Screen())
    assert call(home, CLEAN) == (0, {"screened": 1, "flagged": []})
    assert door.calls == [CLEAN]


def test_a_flagged_report_is_listed_and_exit_1(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    door = stub(monkeypatch, Screen())
    rc, out = call(home, CLEAN, ECHO)
    assert rc == 1
    assert out == {
        "screened": 2,
        "flagged": [
            {
                "artifact_id": str(ECHO),
                "signals": [{"kind": "instruction_echo", "detail": "system directive"}],
            }
        ],
    }
    assert door.calls == [CLEAN, ECHO]


@pytest.mark.parametrize(
    "refusal",
    [NotFoundError("no artifact"), ValidationError("is benchmark-target, not an audit report")],
)
def test_a_refused_id_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, home: Path, refusal: Exception
) -> None:
    stub(monkeypatch, Screen(refusal))
    rc, err = call(home, CLEAN)
    assert rc == 2
    assert str(refusal) in err


def test_an_id_that_is_no_uuid_is_refused_before_any_screen(
    monkeypatch: pytest.MonkeyPatch, home: Path
) -> None:
    door = stub(monkeypatch, Screen())
    with pytest.raises(SystemExit) as exit_:
        call(home, "not-a-uuid")
    assert exit_.value.code == 2
    assert door.calls == []
