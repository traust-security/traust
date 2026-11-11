"""`traust impact enrich|document`: one ExposureService call each, with the services stubbed."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.inventory import DEFAULT_FORGE_HOSTS
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.services.exposure import ExploitContext

from traust.cli import impact
from traust.cli.__main__ import main

APP = "https://github.com/org/app"


class Exposure:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def exploit_context(self, artifacts: dict, repository: Any, deployed: Any) -> ExploitContext:
        self.calls.append((artifacts, repository, deployed))
        return ExploitContext(artifacts=(), reach=None, feeds=())

    def source_document(self, source: str, ident: str) -> bytes:
        self.calls.append((source, ident))
        if source != "nvd":
            raise NotFoundError(f"feed source {source}: not registered (nvd)")
        return b'{"vulnerabilities": []}'


@pytest.fixture
def exposure(monkeypatch: pytest.MonkeyPatch) -> Exposure:
    stub = Exposure()
    core = SimpleNamespace(
        config=SimpleNamespace(forge_hosts=DEFAULT_FORGE_HOSTS),
        services=lambda: SimpleNamespace(exposure=stub),
    )
    monkeypatch.setattr(impact, "_core", lambda config_home: core)
    return stub


def test_enrich_hands_the_artifacts_repository_and_workloads_to_one_call(
    tmp_path: Path, exposure: Exposure, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact = tmp_path / "app-osv.json"
    artifact.write_text('{"candidates": []}')
    workloads = tmp_path / "workloads.json"
    workloads.write_text(json.dumps([APP]))
    out = tmp_path / "enrich.json"
    argv = ["--in", str(artifact), "--repo-url", APP, "--workloads", str(workloads)]
    assert impact.enrich([*argv, "--out", str(out)]) == 0
    url = HttpsRepoUrl.parse(APP, DEFAULT_FORGE_HOSTS)
    assert exposure.calls == [({str(artifact): b'{"candidates": []}'}, url, [url])]
    printed = json.loads(capsys.readouterr().out)
    assert printed == json.loads(out.read_text())
    assert printed["items_with_cves"] == 0 and printed["reach"] is None


def test_enrich_without_a_repository_or_workloads_passes_none(
    tmp_path: Path, exposure: Exposure
) -> None:
    artifact = tmp_path / "a.json"
    artifact.write_text("{}")
    assert impact.enrich(["--in", str(artifact)]) == 0
    assert exposure.calls == [({str(artifact): b"{}"}, None, None)]


@pytest.mark.parametrize(
    ("argv", "error"),
    [
        (["--repo-url", "org/app"], "org/app"),
        (["--workloads", "{broken"], "not JSON"),
        (["--workloads", '["org/app"]'], "org/app"),
        (["--workloads", '{"org/app": true}'], "expected a JSON list of repository URLs"),
    ],
)
def test_enrich_refuses_what_is_not_a_repository_url(
    tmp_path: Path,
    exposure: Exposure,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    error: str,
) -> None:
    artifact = tmp_path / "a.json"
    artifact.write_text("{}")
    if argv[0] == "--workloads":
        (tmp_path / "w.json").write_text(argv[1])
        argv = ["--workloads", str(tmp_path / "w.json")]
    assert impact.enrich(["--in", str(artifact), *argv]) == 2
    assert error in capsys.readouterr().err and exposure.calls == []


def test_document_prints_the_sources_answer(
    exposure: Exposure, capsys: pytest.CaptureFixture[str]
) -> None:
    assert impact.document(["nvd", "CVE-2021-44228"]) == 0
    assert capsys.readouterr().out.strip() == '{"vulnerabilities": []}'
    assert exposure.calls == [("nvd", "CVE-2021-44228")]


def test_document_from_an_unregistered_source_is_refused(
    exposure: Exposure, capsys: pytest.CaptureFixture[str]
) -> None:
    assert impact.document(["csaf", "CVE-2021-44228"]) == 2
    assert "feed source csaf: not registered" in capsys.readouterr().err


@pytest.mark.parametrize("op", ["enrich", "document"])
def test_the_ops_are_on_the_impact_group(op: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_:
        main(["impact", op, "--help"])
    assert exit_.value.code == 0 and f"traust impact {op}" in capsys.readouterr().out
