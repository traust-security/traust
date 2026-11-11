from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import BenchmarkTargetArtifact

from traust.cli import recall

EXAMPLE = Path(__file__).parents[1] / "docs" / "examples" / "benchmark-targets.example.yaml"


@pytest.mark.parametrize("limit", [None, 3])
def test_bootstrap_writes_unrecorded_candidates_as_yaml(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, limit: int | None
) -> None:
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    document = BenchmarkTargetArtifact.from_document(raw)
    calls = []

    def bootstrap_benchmark(*, limit: int) -> BenchmarkTargetArtifact:
        calls.append(limit)
        return document

    quality = SimpleNamespace(bootstrap_benchmark=bootstrap_benchmark)
    monkeypatch.setattr(
        recall,
        "load",
        lambda home: SimpleNamespace(services=lambda: SimpleNamespace(detection_quality=quality)),
    )
    out = tmp_path / "review" / "candidates.yaml"
    argv = ["--out", str(out)]
    if limit is not None:
        argv += ["--limit", str(limit)]
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        assert recall.bootstrap(argv) == 0
    assert calls == [100 if limit is None else limit]
    assert yaml.safe_load(out.read_text(encoding="utf-8")) == json.loads(document.payload)
    assert json.loads(stdout.getvalue()) == {
        "out": str(out),
        "candidates": 1,
        "held_out": 0,
        "admitted": 0,
    }


def test_bootstrap_service_refusal_does_not_write_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def bootstrap_benchmark(*, limit: int) -> BenchmarkTargetArtifact:
        raise ValidationError("benchmark candidate limit must be positive")

    quality = SimpleNamespace(bootstrap_benchmark=bootstrap_benchmark)
    monkeypatch.setattr(
        recall,
        "load",
        lambda home: SimpleNamespace(services=lambda: SimpleNamespace(detection_quality=quality)),
    )
    out = tmp_path / "candidates.yaml"
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        assert recall.bootstrap(["--out", str(out), "--limit", "0"]) == 2
    assert "limit must be positive" in stderr.getvalue()
    assert not out.exists()
