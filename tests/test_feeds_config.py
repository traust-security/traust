"""config/feeds.yaml registry — loader, validation, and URL resolution.

The registry exists so a dead source fails a check instead of 404-ing in
silence, so these tests care most about the ways it could go quietly
wrong: a source with no licence row, an unknown mode, a template that
loses its year segment, and a cache path that resolves into the harness
checkout instead of the workspace.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from traust.registry import feeds_config as fc


def _write(tmp_path: Path, sources: dict) -> Path:
    p = tmp_path / "feeds.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "sources": sources}))
    return p


_LIC = {"id": "CC0-1.0", "terms": "t", "url": "u"}


def test_shipped_registry_loads_and_every_source_is_valid():
    src = fc.load()
    assert src, "the shipped registry must not be empty"
    for sid, spec in src.items():
        assert spec["tier"] in ("cached", "live"), sid
        assert spec["license"]["id"], sid


def test_shipped_registry_covers_both_tiers():
    assert fc.cached_sources() and fc.live_sources()


def test_every_shipped_source_declares_its_consumers():
    """An orphan source is either dead code or an untracked dependency."""
    for sid, spec in fc.load().items():
        assert spec.get("consumers"), f"{sid} names no consumer"


def test_license_block_is_required(tmp_path):
    p = _write(tmp_path, {"x": {"tier": "live", "url_template": "https://h/{ident}"}})
    with pytest.raises(fc.FeedsConfigError, match="license"):
        fc.load(p)


def test_unknown_cached_mode_is_rejected(tmp_path):
    p = _write(
        tmp_path,
        {
            "x": {
                "tier": "cached",
                "mode": "telepathy",
                "url": "https://h/f",
                "file": "f",
                "license": _LIC,
            }
        },
    )
    with pytest.raises(fc.FeedsConfigError, match="unknown cached mode"):
        fc.load(p)


def test_live_source_requires_a_url_template(tmp_path):
    p = _write(tmp_path, {"x": {"tier": "live", "license": _LIC}})
    with pytest.raises(fc.FeedsConfigError, match="url_template"):
        fc.load(p)


def test_indexed_lazy_requires_an_index_file(tmp_path):
    p = _write(tmp_path, {"x": {"tier": "cached", "mode": "indexed-lazy", "license": _LIC}})
    with pytest.raises(fc.FeedsConfigError, match="index_file"):
        fc.load(p)


def test_missing_registry_raises_rather_than_defaulting(tmp_path):
    """Never degrade to an empty registry: that reports 'nothing is
    stale' while tracking nothing at all."""
    with pytest.raises(fc.FeedsConfigError):
        fc.load(tmp_path / "absent.yaml")


def test_unparseable_registry_raises(tmp_path):
    p = tmp_path / "feeds.yaml"
    p.write_text("sources: [this is not a mapping\n")
    with pytest.raises(fc.FeedsConfigError):
        fc.load(p)


def test_max_age_prefers_explicit_then_cadence_then_default():
    assert fc.max_age_hours({"max_age_hours": 6}) == 6
    assert fc.max_age_hours({"cadence": "weekly"}) == 24 * 7
    assert fc.max_age_hours({}) == fc.DEFAULT_MAX_AGE_HOURS
    assert fc.max_age_hours({"max_age_hours": 6}, override=1) == 1


def test_cache_dir_honours_configured_location(tmp_path, monkeypatch):
    import yaml

    from traust.context import load

    home = tmp_path / "cfg"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump({"locations": {"feeds_cache": str(tmp_path / "elsewhere")}}),
        encoding="utf-8",
    )
    fixture = Path(__file__).parent / "fixtures" / "config"
    for name in fixture.iterdir():
        if name.is_file():
            import shutil

            shutil.copy2(name, home / name.name)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)

    assert fc.feeds_cache_dir(core=load()) == tmp_path / "elsewhere"


def test_cache_dir_never_lands_inside_the_harness_checkout(monkeypatch, tmp_path):
    """When workspace is the harness checkout, cache uses progress_tracker."""
    import yaml

    from traust.context import load, progress_tracker_dir
    from traust.paths import HARNESS_ROOT

    tracker = tmp_path / "progress-tracker"
    home = tmp_path / "cfg"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {"locations": {"workspace": str(HARNESS_ROOT), "progress_tracker": str(tracker)}}
        ),
        encoding="utf-8",
    )
    fixture = Path(__file__).parent / "fixtures" / "config"
    for name in fixture.iterdir():
        if name.is_file():
            import shutil

            shutil.copy2(name, home / name.name)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    monkeypatch.chdir(HARNESS_ROOT)
    core = load()
    got = fc.feeds_cache_dir(core=core)
    assert HARNESS_ROOT not in got.parents and got != HARNESS_ROOT
    assert got == progress_tracker_dir(core) / "feeds"


def test_cache_dir_is_not_under_analysis_results(monkeypatch, tmp_path):
    """analysis-results holds work we authored; feeds are third-party
    data with opposite retention and redistribution properties."""
    import yaml

    from traust.context import load

    home = tmp_path / "cfg"
    home.mkdir()
    (home / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "locations": {
                    "workspace": str(tmp_path / "ws"),
                    "analysis_results": str(tmp_path / "ws" / "analysis-results"),
                    "progress_tracker": str(tmp_path / "ws" / "progress-tracker"),
                }
            }
        ),
        encoding="utf-8",
    )
    fixture = Path(__file__).parent / "fixtures" / "config"
    for name in fixture.iterdir():
        if name.is_file():
            import shutil

            shutil.copy2(name, home / name.name)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    assert "analysis-results" not in str(fc.feeds_cache_dir(core=load()))
