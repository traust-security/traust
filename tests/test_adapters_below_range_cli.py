"""`adapters below-range`: refusals, the hand-off to the engine, and the skill's wiring."""

import json
from types import SimpleNamespace

import traust_engine.applicability as applicability
import traust_engine.osv as osv

from traust.cli.groups import GROUPS, adapters
from traust.paths import HARNESS_ROOT

SKILL = HARNESS_ROOT / "harnessing" / "3-audit" / "dependency-watch" / "SKILL.md"


def _args(repo, **kw):
    return SimpleNamespace(
        repo=repo,
        out=None,
        ecosystems="Go,PyPI,npm,Maven,crates.io,RubyGems,NuGet",
        max_candidates=100,
        timeout=5,
        **kw,
    )


def test_registered_under_adapters():
    assert GROUPS["adapters"]["below-range"] is adapters.BELOW_RANGE


def test_not_a_directory(tmp_path):
    assert adapters.call_below_range(None, _args(tmp_path / "missing")) == 2


def test_air_gapped_is_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "air-gapped")
    assert adapters.call_below_range(None, _args(tmp_path)) == 2
    assert "air-gapped" in capsys.readouterr().err


class _Client:
    def __init__(self, *a, failure=None, **kw):
        self._failure = failure

    def probe(self, query):
        return self._failure


def test_unreachable_osv_is_a_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "api")
    monkeypatch.setattr(osv, "OsvClient", lambda *a, **kw: _Client(failure=("unreachable", "dns")))
    assert adapters.call_below_range(None, _args(tmp_path)) == 2


def test_hands_off_to_the_engine_and_summarizes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "api")
    monkeypatch.setattr(osv, "OsvClient", lambda *a, **kw: _Client())
    seen = {}

    def fake_build(repo, out, *, ecosystems, max_candidates, client, fetcher, resolver=None):
        seen.update(repo=repo, out=out, ecosystems=ecosystems, fetcher=fetcher)
        return {
            "installed_exact": 3,
            "candidates": 2,
            "packets": [{"case": "a"}],
            "coverage_gaps": [{"reason": "source_unavailable", "case": "b"}],
            "status": "complete",
        }

    monkeypatch.setattr(applicability, "build", fake_build)
    repo = tmp_path / "svc"
    repo.mkdir()
    assert adapters.call_below_range(None, _args(repo)) == 0
    assert seen["out"] == tmp_path / "svc-below-range"
    assert seen["ecosystems"] == ("Go", "PyPI", "npm", "Maven", "crates.io", "RubyGems", "NuGet")
    summary = json.loads(capsys.readouterr().out)
    assert summary["packets"] == 1 and summary["coverage_gaps"] == {"source_unavailable": 1}


def test_skill_wires_the_mode_with_blind_reviews_and_the_doctrine():
    text = SKILL.read_text()
    assert "Bash(python3 *-m traust.cli adapters below-range:*)" in text
    assert "## Below-range verification" in text
    assert "--tier\n     opus-class fact-judge" in text or "--tier opus-class fact-judge" in text
    assert "never see\n   each other's output" in text or "never see each other's output" in text
    assert "CWE-1427" in text
    assert "--feature-desc below-range-verified" in text


def test_hosts_come_from_feeds_yaml(tmp_path, monkeypatch, capsys):
    from traust.registry.applicability_sources import Hosts

    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "api")
    monkeypatch.setattr(osv, "OsvClient", lambda *a, **kw: _Client())
    hosts = Hosts(
        frozenset({"github.com"}),
        frozenset({"pypi.org"}),
        {"pypi.org": frozenset({"cdn.example"})},
        ("a",),
    )
    monkeypatch.setattr("traust.registry.applicability_sources.applicability_hosts", lambda: hosts)
    seen = {}

    def fake_build(repo, out, *, ecosystems, max_candidates, client, fetcher, resolver=None):
        seen["fetcher"] = fetcher
        return {
            "installed_exact": 0,
            "candidates": 0,
            "packets": [],
            "coverage_gaps": [],
            "status": "complete",
        }

    monkeypatch.setattr(applicability, "build", fake_build)
    repo = tmp_path / "svc"
    repo.mkdir()
    assert adapters.call_below_range(None, _args(repo)) == 0
    f = seen["fetcher"]
    assert f.forges == {"github.com"} and f.registries == {"pypi.org"}
    assert f.redirects == {"pypi.org": frozenset({"cdn.example"})}
    assert "no fix-patches or package-source" not in capsys.readouterr().err


def test_shipped_feeds_yaml_names_every_below_range_host():
    from traust.registry.applicability_sources import applicability_hosts
    from traust.registry.feeds_config import live_sources

    hosts = applicability_hosts(live_sources(HARNESS_ROOT / "config" / "feeds.yaml"))
    assert hosts.forges == {"github.com", "gitlab.com"}
    assert hosts.registries == {
        "proxy.golang.org",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "repo1.maven.org",
        "static.crates.io",
        "rubygems.org",
        "api.nuget.org",
        "github.com",
    }
    assert hosts.redirects["proxy.golang.org"] == {"storage.googleapis.com"}
    assert hosts.redirects["github.com"] == {
        "patch-diff.githubusercontent.com",
        "codeload.github.com",
    }


def test_a_disabled_source_contributes_no_host():
    from traust.registry.applicability_sources import applicability_hosts

    sources = {
        "a": {
            "role": "package-source",
            "url_template": "https://pypi.org/{ident}",
            "access": "disabled",
        },
        "b": {"role": "fix-patches", "url_template": "https://github.com/{ident}.patch"},
    }
    hosts = applicability_hosts(sources)
    assert hosts.registries == frozenset() and hosts.forges == {"github.com"}
    assert applicability_hosts({"x": {"url_template": "https://x.example/"}}) is None


def test_the_deps_dev_resolver_is_passed_and_respects_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr("traust.registry.osv_urls.osv_access", lambda: "api")
    monkeypatch.setattr(osv, "OsvClient", lambda *a, **kw: _Client())
    seen = []

    def fake_build(repo, out, *, ecosystems, max_candidates, client, fetcher, resolver=None):
        seen.append(resolver)
        return {
            "installed_exact": 0,
            "candidates": 0,
            "packets": [],
            "coverage_gaps": [],
            "status": "complete",
        }

    monkeypatch.setattr(applicability, "build", fake_build)
    repo = tmp_path / "svc"
    repo.mkdir()
    monkeypatch.setattr(
        "traust.registry.osv_urls.deps_dev_settings", lambda: ("https://api.deps.dev", "api")
    )
    assert adapters.call_below_range(None, _args(repo)) == 0
    monkeypatch.setattr(
        "traust.registry.osv_urls.deps_dev_settings", lambda: ("https://api.deps.dev", "disabled")
    )
    assert adapters.call_below_range(None, _args(repo)) == 0
    from traust_engine.depsdev import DepsDevClient

    assert isinstance(seen[0], DepsDevClient) and seen[1] is None
