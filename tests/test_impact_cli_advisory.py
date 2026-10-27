"""`traust impact analyze` takes the advisory from the feeds registry, never a typed range."""

from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from traust.cli.groups import impact


def _args(*argv):
    ap = argparse.ArgumentParser()
    impact.add_analyze_args(ap)
    return ap.parse_args(
        ["GHSA-aaaa-bbbb-cccc", "--module", "brotli", "--ecosystem", "pypi", *argv]
    )


class _Engine:
    def __init__(self):
        self.calls = []
        self.impact = SimpleNamespace(analyze=lambda **kw: self.calls.append(kw) or 0)


def test_the_range_flags_are_gone():
    with pytest.raises(SystemExit):
        _args("--vulnerable-range", "<1.2.1")
    with pytest.raises(SystemExit):
        _args("--fixed-version", "1.2.1")


def test_the_osv_url_comes_from_the_feeds_registry(monkeypatch):
    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "api")
    monkeypatch.setattr(
        "traust.registry.osv_urls.osv_query_url", lambda: "https://osv.test/v1/query"
    )
    engine = _Engine()
    args = _args("--verified-version", "1.0.2", "--verified-by", "verdicts.json")
    assert impact.call_analyze(engine, args) == 0
    [call] = engine.calls
    assert call["osv_url"] == "https://osv.test/v1/query"
    assert (call["verified_versions"], call["verified_by"]) == (("1.0.2",), "verdicts.json")
    assert "vulnerable_range" not in call and "fixed_version" not in call


def test_air_gapped_needs_the_advisory_record(monkeypatch, capsys):
    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "air-gapped")
    engine = _Engine()
    assert impact.call_analyze(engine, _args()) == 2
    assert engine.calls == [] and "--advisory-file" in capsys.readouterr().err
    assert impact.call_analyze(engine, _args("--advisory-file", "ghsa.json")) == 0
    assert engine.calls[0]["advisory_file"] == "ghsa.json"
