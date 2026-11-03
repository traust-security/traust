from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Callable
from pathlib import Path
from uuid import UUID, uuid4

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


def test_collect_then_reverse_queries_read_persisted_reference_facts(
    core: Context,
    tmp_path: Path,
) -> None:
    ref_id = registered(core, "library", "a" * 40)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "go.mod").write_text("module example.test/library\n")
    (checkout / "api.go").write_text("""package library
import "example.test/upstream/api"
func Public() {}
""")
    (checkout / "crd.yaml").write_text("""apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: widgets.widgets.example.test}
spec:
  group: widgets.example.test
  names: {kind: Widget, plural: widgets}
  scope: Namespaced
""")
    code, collected = invoke(
        portfolio_facts.collect,
        "--repository-ref-id",
        str(ref_id),
        "--checkout",
        f"{ref_id}={checkout}",
    )
    assert code == 0
    artifact_id = collected[0]["artifact_id"]
    code, imports = invoke(
        portfolio_facts.imports_package,
        "example.test/upstream",
        "--repository-ref-id",
        str(ref_id),
    )
    assert code == 0
    assert [(r["artifact_id"], r["fact"]["package"]) for r in imports] == [
        (artifact_id, "example.test/upstream/api"),
    ]
    code, exports = invoke(portfolio_facts.exports_of, "--repository-ref-id", str(ref_id))
    assert code == 0
    assert [r["fact"]["name"] for r in exports] == ["Public"]
    code, interfaces = invoke(
        portfolio_facts.crd_consumers,
        "widgets.example.test",
        "--repository-ref-id",
        str(ref_id),
    )
    assert code == 0
    assert [(r["artifact_id"], r["fact"]["role"]) for r in interfaces] == [(artifact_id, "owner")]
    repository_id = core.services().portfolio.inventory.get_ref(ref_id).repository_id
    code, coupling = invoke(
        portfolio_facts.internal_coupling,
        "--repository-id",
        str(repository_id),
    )
    assert code == 0
    assert coupling[0]["consumer_repository_ids"] == []
    assert coupling[0]["packages"][0]["source_repository_id"] == str(repository_id)


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


def test_checkout_mapping_must_name_a_selected_ref(core: Context, tmp_path: Path) -> None:
    ref_id = registered(core, "source", "d" * 40)
    code, _ = invoke(
        portfolio_facts.collect,
        "--repository-ref-id",
        str(ref_id),
        "--checkout",
        f"{uuid4()}={tmp_path}",
    )
    assert code == 2
