from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from traust.context import feeds_cache_dir, load

STAMP = datetime(2026, 10, 1, tzinfo=UTC)


def registry(directory: Path) -> None:
    directory.mkdir(parents=True)
    (directory / "product_definitions.json").write_text(
        json.dumps({"ps_products": {}, "ps_modules": {}, "ps_update_streams": {}})
    )
    (directory / "feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": STAMP.isoformat()}})
    )


@pytest.mark.parametrize("location", ["configured", "environment", "tracker-default"])
def test_core_registry_age_reads_the_same_cache_as_the_fetcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    home = tmp_path / "config"
    home.mkdir()
    tracker = tmp_path / "tracker"
    configured = tmp_path / "configured-cache"
    environment = tmp_path / "shared-cache"
    expected = {
        "configured": configured,
        "environment": environment,
        "tracker-default": tracker / "feeds",
    }[location]
    locations = {"progress_tracker": str(tracker)}
    if location != "tracker-default":
        locations["feeds_cache"] = str(configured)
    (home / "traust.yaml").write_text(
        yaml.safe_dump({"home": str(tmp_path / "state"), "locations": locations})
    )
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    if location == "environment":
        monkeypatch.setenv("FEEDS_CACHE_DIR", str(environment))
    registry(expected)
    core = load(home)
    assert feeds_cache_dir(core) == expected
    assert core.config.locations.feeds_cache_dir() == expected
    assert core.product_definitions().status().fetched_at == STAMP


def test_cli_load_registers_the_actual_review_reference_not_the_template(tmp_path: Path) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "state")}))
    (home / "reachability-watch.yaml").write_text(
        "reviewed: 2026-10-01\nreview_cadence_days: 30\nwatch: []\n"
    )
    review = load(home).reachability_review.read()
    assert review is not None
    assert review.reviewed == STAMP.date()
    assert review.review_cadence_days == 30


def test_absent_review_reference_is_not_recorded_as_reviewed(tmp_path: Path) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "state")}))
    assert load(home).reachability_review.read() is None
