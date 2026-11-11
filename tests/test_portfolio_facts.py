from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli import portfolio_facts


def invoke(command: Callable[[list[str]], int], *argv: str) -> tuple[int, object]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = command(list(argv))
    return result, json.loads(out.getvalue()) if out.getvalue() else err.getvalue()


@pytest.fixture
def core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Context:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(portfolio_facts, "load", lambda config_home: core)
    return core


def registered(core: Context, name: str, sha: str) -> UUID:
    portfolio = core.services().portfolio
    repository = portfolio.register_repository(
        HttpsRepoUrl.parse(f"https://github.com/example/{name}", core.config.forge_hosts),
        True,
    )
    assert repository.id is not None
    ref = portfolio.register_ref(repository.id, GitSha.parse(sha), None, None)
    assert ref.id is not None
    return ref.id


def test_images_shipping_module_query_uses_recorded_sbom_and_version(core: Context) -> None:
    ref_id = registered(core, "image-source", "b" * 40)
    image = core.services().exposure.ingest_image_sbom(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "name": "example.test/library",
                        "version": "v1.0.0",
                        "type": "library",
                        "purl": "pkg:golang/example.test/library@v1.0.0",
                    }
                ],
            }
        ).encode(),
        "sha256:" + "c" * 64,
        repository_ref_id=ref_id,
    )
    code, shipped = invoke(portfolio_facts.ships_module, "example.test/library")
    assert code == 0
    assert [(r["image_id"], r["repository_ref_id"]) for r in shipped] == [
        (str(image.id), str(ref_id)),
    ]
    assert invoke(
        portfolio_facts.ships_module,
        "example.test/library",
        "--version",
        "v2.0.0",
    ) == (0, [])
    code, _ = invoke(
        portfolio_facts.ships_module,
        "example.test/library",
        "--ecosystem",
        "npm",
    )
    assert code == 2
