"""Workspace/sibling resolution for backport-fix (_harness_paths.py).

Pins the traust-internal convention rather than a fixed parent count: the
skill already moved one tier deeper once, and every depth-based lookup broke
silently (publish-by-default landed inside the checkout; VERSION reads always
missed). Run: ../traust/.venv/bin/python -m pytest tests/test_backport_paths.py
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SCRIPTS = REPO / "harnessing" / "7-remediate" / "backport-fix" / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), _SCRIPTS / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


paths = _load("_harness_paths.py")


def _workspace(tmp_path: pathlib.Path, *, corpus: bool = True, harness: str = "") -> pathlib.Path:
    if corpus:
        (tmp_path / "analysis-results").mkdir()
    if harness:
        h = tmp_path / "traust"
        h.mkdir()
        (h / "VERSION").write_text(harness + "\n")
    return tmp_path


def test_repo_root_points_at_this_checkout():
    root = paths.repo_root()
    assert (root / "harnessing" / "7-remediate" / "backport-fix").is_dir()
    assert root == REPO


def test_workspace_honours_the_override(monkeypatch, tmp_path):
    ws = _workspace(tmp_path)
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    assert paths.workspace_root() == ws


def test_required_workspace_fails_loud_without_a_corpus(monkeypatch, tmp_path):
    ws = _workspace(tmp_path, corpus=False)
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    with pytest.raises(SystemExit):
        paths.workspace_root(required=True)


def test_absolute_corpus_root_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_RESULTS_ROOT", str(tmp_path / "elsewhere"))
    assert paths.analysis_results_root() == tmp_path / "elsewhere"


def test_relative_corpus_root_resolves_against_the_workspace(monkeypatch, tmp_path):
    ws = _workspace(tmp_path)
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    monkeypatch.setenv("AUDIT_RESULTS_ROOT", "corpus")
    assert paths.analysis_results_root() == (ws / "corpus").resolve()


def test_corpus_root_defaults_to_the_workspace_sibling(monkeypatch, tmp_path):
    ws = _workspace(tmp_path)
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    monkeypatch.delenv("AUDIT_RESULTS_ROOT", raising=False)
    # Never inside the checkout: that is exactly the off-by-one that made
    # publish-by-default write to <repo>/analysis-results.
    root = paths.analysis_results_root()
    assert root == ws / "analysis-results"
    assert REPO not in root.parents


def test_harness_version_reads_this_checkout_when_it_is_the_harness():
    # Inside traust itself, repo_root carries VERSION; no sibling needed.
    assert paths.harness_root() == REPO
    assert paths.harness_version() == (REPO / "VERSION").read_text().strip()


def test_harness_version_reads_the_sibling_checkout(monkeypatch, tmp_path):
    bare = tmp_path / "checkout"
    bare.mkdir()
    monkeypatch.setattr(paths, "repo_root", lambda: bare)
    ws = _workspace(tmp_path, harness="1.2.3")
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    assert paths.harness_root() == ws / "traust"
    assert paths.harness_version() == "1.2.3"


def test_harness_version_is_honest_when_the_sibling_is_absent(monkeypatch, tmp_path):
    bare = tmp_path / "checkout"
    bare.mkdir()
    monkeypatch.setattr(paths, "repo_root", lambda: bare)
    ws = _workspace(tmp_path)
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    assert paths.harness_root() is None
    # A fabricated number would misattribute every report's provenance.
    assert paths.harness_version() == "0.0.0"


def test_harness_version_rejects_a_non_semver_file(monkeypatch, tmp_path):
    bare = tmp_path / "checkout"
    bare.mkdir()
    (bare / "VERSION").write_text("not-a-version")
    monkeypatch.setattr(paths, "repo_root", lambda: bare)
    assert paths.harness_version() == "0.0.0"


def test_emitter_publish_root_matches_the_shared_resolution(monkeypatch, tmp_path):
    emit = _load("emit_backport_report.py")
    ws = _workspace(tmp_path)
    monkeypatch.setenv("HARNESS_WORKSPACE", str(ws))
    monkeypatch.delenv("AUDIT_RESULTS_ROOT", raising=False)
    assert emit.default_publish_root() == paths.analysis_results_root()
