"""The live spend view and `attribute-spend` read files only: on a fresh install they never create
the record store (`<core home>/traust.db`). `registry products` reads the recorded product map."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.context import Context
from traust_core.v1.providers.transcripts import SessionTranscripts

from traust.cli.groups import metrics, registry

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
PRODUCT_DEFINITIONS = Path(__file__).parent / "fixtures" / "registry" / "product-definitions"
WORKSPACE = Path("/w/workspace")
DAY = "2026-10-05"


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "projects" / "-w-workspace"
    project.mkdir(parents=True)
    usage = {"input_tokens": 1200, "output_tokens": 300}
    record = {
        "timestamp": f"{DAY}T08:00:00Z",
        "message": {"model": "claude-opus-5-5", "usage": usage},
    }
    (project / "s1.jsonl").write_text(json.dumps(record) + "\n")
    monkeypatch.setattr(Context, "session_transcripts", SessionTranscripts(tmp_path / "projects"))
    home = tmp_path / "config"
    home.mkdir()
    (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    (home / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    return home


def run(fn: Any, args: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = fn(args)
    return rc, out.getvalue()


def spend_args(config: Path, **kw: Any) -> Any:
    values = {"workspace": WORKSPACE, "date": DAY, "month": None, "json": False, "append": False}
    return SimpleNamespace(config_home=config, reconcile=False, **{**values, **kw})


@pytest.mark.parametrize(
    ("call", "kw"),
    [
        (metrics.call_collect_spend, {}),
        (metrics.call_attribute_spend, {}),
        (metrics.call_attribute_spend, {"json": True}),
    ],
)
def test_the_spend_views_never_create_the_record_store(
    config: Path, tmp_path: Path, call: Any, kw: dict[str, Any]
) -> None:
    rc, out = run(call, spend_args(config, **kw))
    assert rc == 0 and out
    assert not (tmp_path / "store" / "traust.db").exists()


def products_args(config: Path, tmp_path: Path) -> Any:
    cache = shutil.copytree(PRODUCT_DEFINITIONS, tmp_path / "feeds")
    return SimpleNamespace(
        config_home=config,
        package=["widget-core"],
        repo_url=[],
        product=[],
        all=False,
        cache_dir=Path(cache),
        json=True,
    )


def test_registry_products_says_when_no_map_is_recorded(config: Path, tmp_path: Path) -> None:
    rc, out = run(registry.call_products, products_args(config, tmp_path))
    doc = json.loads(out)
    assert rc == 0 and doc["warnings"][0] == registry.NO_MAP
    assert [r["match_tier"] for r in doc["results"]] == ["none"]


def test_registry_products_uses_the_recorded_map(config: Path, tmp_path: Path) -> None:
    mapping = tmp_path / "map.yaml"
    mapping.write_text("mappings:\n  packages:\n    widget-core: widget\n")
    recorded = SimpleNamespace(config_home=config, map=mapping)
    assert run(registry.call_product_map, recorded)[0] == 0
    rc, out = run(registry.call_products, products_args(config, tmp_path))
    doc = json.loads(out)
    assert rc == 0 and registry.NO_MAP not in doc.get("warnings", [])
    assert [r["match_tier"] for r in doc["results"]] == ["mapped"]


def test_a_malformed_map_is_refused(config: Path, tmp_path: Path) -> None:
    mapping = tmp_path / "map.yaml"
    mapping.write_text("mappings:\n  packages:\n    widget-core: 1\n")
    assert run(registry.call_product_map, SimpleNamespace(config_home=config, map=mapping))[0] == 2


def test_appending_spend_does_record(config: Path, tmp_path: Path) -> None:
    rc, _ = run(metrics.call_collect_spend, spend_args(config, append=True))
    assert rc == 0
    assert (tmp_path / "store" / "traust.db").exists()
