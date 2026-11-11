"""`traust sweep benchmark-targets`: the CLI layer only. The manifest becomes one
`DetectionQualityService.record`; a refused answer key is exit 2. The door is traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import BenchmarkTargetArtifact

from traust.cli import recall

EXAMPLE = Path(__file__).parents[1] / "docs" / "examples" / "benchmark-targets.example.yaml"
RECORDED = uuid.uuid4()


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def record(monkeypatch: pytest.MonkeyPatch) -> Door:
    door = Door(SimpleNamespace(artifact_id=RECORDED))
    services = SimpleNamespace(detection_quality=SimpleNamespace(record=door))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(home: Path, manifest: Path) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = recall.targets(["--config-home", str(home), str(manifest)])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_the_manifest_is_recorded_as_the_answer_key(record: Door, home: Path) -> None:
    rc, out = call(home, EXAMPLE)
    assert (rc, out) == (0, {"artifact_id": str(RECORDED), "version": 1})
    ((doc, source),) = record.calls
    assert isinstance(doc, BenchmarkTargetArtifact)
    assert source.source == "interactive"


def test_yaml_dates_reach_the_schema_as_iso_strings(
    record: Door, home: Path, tmp_path: Path
) -> None:
    manifest = tmp_path / "m.yaml"
    raw = yaml.safe_load(EXAMPLE.read_text())
    manifest.write_text(yaml.safe_dump({**raw, "updated": date(2026, 1, 1)}))
    assert "updated: 2026-01-01\n" in manifest.read_text()
    rc, _ = call(home, manifest)
    assert rc == 0
    ((doc, _),) = record.calls
    assert json.loads(doc.payload)["updated"] == "2026-01-01"


def test_a_manifest_that_fails_its_schema_is_exit_2(
    record: Door, home: Path, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"version": 1, "targets": [{"id": "x"}]}))
    rc, err = call(home, bad)
    assert rc == 2 and "benchmark-target" in err
    assert not record.calls


def test_a_refused_answer_key_is_exit_2(record: Door, home: Path) -> None:
    record.result = ValidationError("benchmark answer key: duplicate target ids ['bt-1']")
    rc, err = call(home, EXAMPLE)
    assert rc == 2 and "duplicate target ids" in err
