#!/usr/bin/env python3
"""Tests for check_drift.check_docs_product_map — the future-doc-version
catcher (doc-variance lane P3 drift rule). Offline: live enumeration
is stubbed."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
from traust.cli import check_drift as cd

MAP = """
version: 1
fetched_at: "2026-07-30"
products:
  fict_product:
    versions: ["4.12", "4.13"]
    version_to_refs: {mode: head}
    matched_by: curated
    confirmed: false
"""


def _ws(tmp_path, map_text=MAP):
    d = tmp_path / "inputs" / "adhoc"
    d.mkdir(parents=True)
    (d / "docs-product-map.yaml").write_text(map_text)
    return d.parent


def _rows(ws, live, monkeypatch):
    monkeypatch.setattr(cd, "_docs_live_versions", lambda slug: live)
    return cd.check_docs_product_map(ws)


def test_future_version_is_drift(tmp_path, monkeypatch):
    rows = _rows(_ws(tmp_path), ["3.9", "4.12", "4.13", "4.14"], monkeypatch)
    [r] = [r for r in rows if r["item"] == "docs-versions:fict_product"]
    assert r["status"] == "drift"
    assert "4.14" in r["detail"]
    assert "3.9" not in r["detail"]  # below-window = historical, ignored


def test_matching_window_is_fresh(tmp_path, monkeypatch):
    rows = _rows(_ws(tmp_path), ["3.9", "4.12", "4.13"], monkeypatch)
    [r] = [r for r in rows if r["item"] == "docs-versions:fict_product"]
    assert r["status"] == "fresh"


def test_retired_version_is_drift(tmp_path, monkeypatch):
    rows = _rows(_ws(tmp_path), ["4.12"], monkeypatch)
    [r] = [r for r in rows if r["item"] == "docs-versions:fict_product"]
    assert r["status"] == "drift" and "4.13" in r["detail"]


def test_network_failure_is_unavailable_never_fresh(tmp_path, monkeypatch):
    rows = _rows(_ws(tmp_path), None, monkeypatch)
    [r] = [r for r in rows if r["item"] == "docs-versions:fict_product"]
    assert r["status"] == "unavailable"
    assert "NOT treated as fresh" in r["detail"]


def test_absent_map_is_pending(tmp_path):
    assert cd.check_docs_product_map(tmp_path)[0]["status"] == "pending"


def test_old_map_is_stale(tmp_path, monkeypatch):
    old = MAP.replace('"2026-07-30"', '"2026-01-01"')
    rows = _rows(_ws(tmp_path, old), ["4.12", "4.13"], monkeypatch)
    assert any(r["item"] == "docs-product-map" and r["status"] == "stale" for r in rows)
