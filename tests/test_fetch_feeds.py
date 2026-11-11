"""Tests for traust.cli.fetch_feeds (product-definitions)."""

import json

import pytest

from traust.cli import fetch_feeds as ff
from traust.context import load


@pytest.fixture(autouse=True)
def _product_definitions_configured(monkeypatch, tmp_path):
    """product-definitions is config-gated (locations.product_definitions) since it
    targets a deployment-specific registry. The suite exercises it as a configured
    estate would. Tests that want the open-source default (absent) override it."""
    home = tmp_path / "config-home"
    home.mkdir()
    (home / "traust.yaml").write_text(f"locations:\n  product_definitions: {URL}\n")
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))


def test_product_definitions_absent_without_config(tmp_path, capsys):
    """Open-source default: locations.product_definitions unset → the internal
    product registry is not registered at all; nothing is fetched, the run says so."""
    (tmp_path / "config-home" / "traust.yaml").unlink()
    assert ff.main(["--cache-dir", str(tmp_path)]) == 1
    assert "not configured" in capsys.readouterr().out
    assert not (tmp_path / "product_definitions.json").exists()


URL = "https://feeds.test/product-definitions.json"


def _mk_cache(tmp_path, retrieved_at="2026-07-18T00:00:00Z"):
    cache = tmp_path / "feeds"
    cache.mkdir()
    (cache / "product_definitions.json").write_text(
        json.dumps({"ps_products": {"a": {}}, "ps_modules": {}, "ps_update_streams": {}})
    )
    (cache / "feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": retrieved_at}})
    )
    return cache


# ---------------- fetch_feeds (product-definitions) ----------------


def test_offline_uses_stale_copy(tmp_path):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    usable, status = ff.fetch(URL, cache, 24, offline=True)
    assert usable and "STALE" in status


def test_offline_without_copy_fails(tmp_path):
    usable, _status = ff.fetch(URL, tmp_path / "empty", 24, offline=True)
    assert not usable


def test_fresh_copy_skips_download(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at=ff._iso(ff._now()))
    monkeypatch.setattr(
        ff.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network touched")),
    )
    usable, status = ff.fetch(URL, cache, 24)
    assert usable and status.startswith("fresh")


def test_failed_refresh_falls_back(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    import urllib.error

    monkeypatch.setattr(
        ff.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("no vpn")),
    )
    usable, status = ff.fetch(URL, cache, 24)
    assert usable and "STALE" in status and "refresh failed" in status


def test_a_refresh_writes_the_registry_and_its_counts(tmp_path, monkeypatch):
    body = json.dumps({"ps_products": {"a": {}, "b": {}}, "ps_modules": {}}).encode()

    class _Resp:
        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ff.urllib.request, "urlopen", lambda *a, **k: _Resp())
    cache = tmp_path / "feeds"
    assert ff.main(["--cache-dir", str(cache)]) == 0
    assert (cache / "product_definitions.json").read_bytes() == body
    meta = json.loads((cache / "feeds-meta.json").read_text())["product-definitions"]
    assert meta["counts"] == {"ps_modules": 0, "ps_products": 2} and meta["url"] == URL


# ---------------- product-definitions loader shape guard ----------------


def _write_pd(cache, doc):
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "product_definitions.json").write_text(json.dumps(doc))


def _read_pd(cache):
    return load().product_definitions(cache).read()


def test_load_product_definitions_happy(tmp_path):
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {"a": {}}, "ps_modules": {"a-1": {}}, "ps_update_streams": {}})
    doc = _read_pd(cache).document
    assert doc["ps_products"] == {"a": {}}


def test_load_product_definitions_is_unavailable_on_missing_key(tmp_path):
    """A silent upstream shape change must not read as 'no contacts'."""
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {}, "ps_update_streams": {}})
    snapshot = _read_pd(cache)
    assert snapshot.document is None and snapshot.status == "unavailable"
    assert "ps_modules" in snapshot.source.detail


def test_load_product_definitions_is_unavailable_on_wrong_type(tmp_path):
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {}, "ps_modules": [], "ps_update_streams": {}})
    snapshot = _read_pd(cache)
    assert snapshot.document is None and snapshot.status == "unavailable"
    assert "ps_modules" in snapshot.source.detail
