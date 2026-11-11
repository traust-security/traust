"""`traust sweep build-canaries`: the CLI layer only. The canary (or seeded) sources dir picks the
engine materialiser, then one `DetectionQualityService.build_canaries`; a refusal is exit 2."""

from __future__ import annotations

import contextlib
import io
import json
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import ConfigError

from traust.cli import recall

BUILT = SimpleNamespace(
    target_id="bt-canary-demo", repo=SimpleNamespace(repo_url="file:///c/demo", sha="a" * 40)
)


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    seen = SimpleNamespace(canaries=[], provenance=[], result=[BUILT])

    def build_canaries(provenance: Any) -> Any:
        seen.provenance.append(provenance)
        if isinstance(seen.result, Exception):
            raise seen.result
        return seen.result

    def load(home: Any, *, canaries: str) -> Any:
        seen.canaries.append(canaries)
        quality = SimpleNamespace(build_canaries=build_canaries)
        return SimpleNamespace(services=lambda: SimpleNamespace(detection_quality=quality))

    monkeypatch.setattr(recall, "load", load)
    return seen


def call(*argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = recall.canaries(list(argv))
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.mark.parametrize(("flags", "sources"), [((), "canaries"), (("--seeded",), "seeded")])
def test_the_sources_dir_feeds_one_build(
    wired: SimpleNamespace, flags: tuple[str, ...], sources: str
) -> None:
    rc, out = call(*flags)
    assert rc == 0
    assert out == [{"target_id": "bt-canary-demo", "repo_url": "file:///c/demo", "sha": "a" * 40}]
    assert wired.canaries == [sources]
    assert wired.provenance[0].source == "interactive"


def test_nothing_built_prints_an_empty_list(wired: SimpleNamespace) -> None:
    wired.result = []
    assert call() == (0, [])


def test_missing_sources_are_exit_2(wired: SimpleNamespace) -> None:
    wired.result = ConfigError("no canary sources at /cfg/recall-benchmark/canaries")
    rc, err = call()
    assert rc == 2 and "no canary sources" in err
