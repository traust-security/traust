"""Tests for traust.cli.fetch_feeds + enrich_findings_cves.py (C8)."""

import gzip
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml
from traust_contracts import Locations

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    import importlib

    if name == "fetch_feeds":
        return importlib.import_module("traust.cli.fetch_feeds")
    path = skill_dir("secure-code-audit") / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ff = _load("fetch_feeds")
en = _load("enrich_findings_cves")


@pytest.fixture(autouse=True)
def _product_definitions_configured(tmp_path, monkeypatch):
    """product-definitions is config-gated (locations.product_definitions) since it
    targets a deployment-specific registry. The suite exercises it as a configured
    estate would; the lazy feeds cache is reset so the gate is re-evaluated per
    test. Tests that want the open-source default (absent) override it."""
    home = tmp_path / "configured-home"
    shutil.copytree(os.environ["TRAUST_CONFIG_HOME"], home)
    loc_path = home / "locations.yaml"
    loc = yaml.safe_load(loc_path.read_text())
    loc["product_definitions"] = "https://feeds.test/product-definitions.json"
    loc_path.write_text(yaml.safe_dump(loc), encoding="utf-8")
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    monkeypatch.setattr(
        ff.locations,
        "configured_locations",
        lambda: Locations(product_definitions="https://feeds.test/product-definitions.json"),
    )
    monkeypatch.setattr(ff, "_FEEDS_CACHE", None)
    yield
    ff._FEEDS_CACHE = None


def test_product_definitions_absent_without_config(monkeypatch):
    """Open-source default: locations.product_definitions unset → the internal
    product registry is not registered at all; consumers degrade, nothing errors."""
    monkeypatch.setattr(ff.locations, "configured_locations", lambda: Locations())
    monkeypatch.setattr(ff, "_FEEDS_CACHE", None)
    assert "product-definitions" not in ff.FEEDS
    assert "product-definitions" not in ff.public_feeds()


def _mk_cache(tmp_path, retrieved_at="2026-07-18T00:00:00Z"):
    cache = tmp_path / "feeds"
    cache.mkdir()
    csv = (
        "#model_version:v2026.06.15,score_date:2026-07-18\n"
        "cve,epss,percentile\n"
        "CVE-2026-1111,0.72000,0.99120\n"
        "CVE-2026-2222,0.00042,0.05000\n"
    )
    (cache / "epss_scores-current.csv.gz").write_bytes(gzip.compress(csv.encode()))
    # vex is indexed-lazy: its cadence artifact is the synced index
    (cache / "vex").mkdir(exist_ok=True)
    (cache / "vex" / "changes.csv").write_text(
        '"2026/cve-2026-4444.json","2026-07-18T00:00:00+00:00"\n'
    )
    (cache / "known_exploited_vulnerabilities.json").write_text(
        json.dumps(
            {
                "catalogVersion": "2026.07.16",
                "count": 1,
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-3333",
                        "dateAdded": "2026-07-01",
                        "knownRansomwareCampaignUse": "Known",
                        "vulnerabilityName": "Demo RCE",
                    }
                ],
            }
        )
    )
    (cache / "rh_cve.json").write_text(
        json.dumps(
            [
                {
                    "CVE": "CVE-2026-4444",
                    "public_date": "2026-07-01T00:00:00Z",
                    "bugzilla_description": "demo-operator: demo-operator: demo issue",
                    "severity": "important",
                    "cvss3_score": 7.5,
                    "CWE": "CWE-863",
                }
            ]
        )
    )
    (cache / "feeds-meta.json").write_text(
        json.dumps(
            {
                "epss": {"retrieved_at": retrieved_at, "feed_version": "v-test"},
                "kev": {"retrieved_at": retrieved_at, "feed_version": "2026.07.16"},
                "rh-cve": {"retrieved_at": retrieved_at, "watermark": "2026-07-01", "count": 1},
            }
        )
    )
    return cache


# ---------------- fetch_feeds ----------------


def test_loaders(tmp_path):
    cache = _mk_cache(tmp_path)
    epss = ff.load_epss(cache)
    assert epss["CVE-2026-1111"]["epss"] == 0.72
    assert len(epss) == 2
    kev = ff.load_kev(cache)
    assert kev["CVE-2026-3333"]["ransomware"] is True


def test_feed_status_staleness(tmp_path):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    st = ff.feed_status(cache, max_age_hours=24)
    assert st["epss"]["stale"] and st["kev"]["stale"]
    st2 = ff.feed_status(cache, max_age_hours=10**6)
    assert not st2["epss"]["stale"]


def test_offline_uses_stale_copy(tmp_path):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    usable, status = ff.fetch("epss", cache, 24, offline=True)
    assert usable and "STALE" in status


def test_offline_without_copy_fails(tmp_path):
    usable, _status = ff.fetch("kev", tmp_path / "empty", 24, offline=True)
    assert not usable


def test_fresh_copy_skips_download(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at=ff._iso(ff._now()))
    monkeypatch.setattr(
        ff.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network touched")),
    )
    usable, status = ff.fetch("epss", cache, 24)
    assert usable and status.startswith("fresh")


def test_failed_refresh_falls_back(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    import urllib.error

    monkeypatch.setattr(
        ff.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("no vpn")),
    )
    usable, status = ff.fetch("epss", cache, 24)
    assert usable and "STALE" in status and "refresh failed" in status


# ---------------- enrich_findings_cves ----------------


def test_enrich_items_join(tmp_path):
    cache = _mk_cache(tmp_path)
    epss, kev = ff.load_epss(cache), ff.load_kev(cache)
    items = [
        {"id": "F-1", "description": "fixes CVE-2026-1111 in dep"},
        {"id": "F-2", "title": "ransomware CVE-2026-3333"},
        {"id": "F-3", "title": "no cve here"},
    ]
    out = en.enrich_items(items, epss, kev)
    assert [i["id"] for i in out] == ["F-1", "F-2"]
    assert out[0]["max_epss"] == 0.72 and not out[0]["kev_any"]
    assert out[1]["kev_any"] and out[1]["cves"][0]["kev_ransomware"]


def test_repo_label():
    assert (
        en.repo_label({"metadata": {"repository": "https://github.com/stolostron/foo.git"}})
        == "stolostron/foo"
    )
    assert en.repo_label({"metadata": {"repository": "/tmp/x"}}) is None


def test_main_end_to_end(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path)
    artifact = tmp_path / "x-osv-scanner.json"
    artifact.write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://github.com/org/app"},
                "candidates": [{"osv_id": "GHSA-x", "aliases": ["CVE-2026-3333"]}],
            }
        )
    )
    graph = tmp_path / "repo-graph.json"
    graph.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "repo:github.com/org/app", "type": "repo", "label": "org/app"},
                    {"id": "product:acm", "type": "product", "label": "ACM"},
                ],
                "edges": [
                    {"rel": "ships", "from": "product:acm", "to": "repo:github.com/org/app"},
                    {
                        "rel": "owned-by",
                        "from": "repo:github.com/org/app",
                        "to": "team:example-team",
                    },
                ],
            }
        )
    )
    workloads = tmp_path / "workloads.json"
    workloads.write_text(json.dumps(["org/app"]))
    out = tmp_path / "enrich.json"
    rc = en.main(
        [
            "--in",
            str(artifact),
            "--cache-dir",
            str(cache),
            "--repo-graph",
            str(graph),
            "--workloads",
            str(workloads),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    src = doc["sources"][0]
    assert src["items"][0]["kev_any"] is True
    reach = src["repository_reach"]
    assert reach["products_shipping"] == ["ACM"]
    assert reach["owner_team"] == "example-team"
    assert reach["deployed"] is True
    assert doc["summary"] == {"items_with_cves": 1, "kev_hits": 1}


def test_main_without_workloads_is_unknown(tmp_path):
    cache = _mk_cache(tmp_path)
    artifact = tmp_path / "y.json"
    artifact.write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://github.com/org/app"},
                "findings": [{"id": "F-9", "title": "CVE-2026-2222 dep"}],
            }
        )
    )
    out = tmp_path / "e2.json"
    rc = en.main(
        [
            "--in",
            str(artifact),
            "--cache-dir",
            str(cache),
            "--repo-graph",
            str(tmp_path / "absent.json"),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["sources"][0]["repository_reach"]["deployed"] == "unknown"


# ---------------- internal-feed gating (v0.222.0) ----------------


def test_all_excludes_internal_feeds(tmp_path):
    """`--feed all` is what unattended lanes invoke.

    harnessing/3-audit/dependency-watch runs fetch_feeds.py bare on a daily
    cadence and main() returns 1 for an unusable feed, so a VPN-only feed
    in the default set would fail that lane on every off-VPN run.
    """
    assert "product-definitions" in ff.FEEDS
    assert "product-definitions" not in ff.public_feeds()
    # Compare against the registry, not a literal: a hardcoded set is how
    # a newly added feed drops out of the unattended lane unnoticed.
    from traust.registry import feeds_config as fc

    assert set(ff.public_feeds()) == set(fc.cached_sources())
    assert "vex" in ff.public_feeds()


def test_all_offline_does_not_touch_internal_feed(tmp_path):
    cache = _mk_cache(tmp_path)
    rc = ff.main(["--cache-dir", str(cache), "--feed", "all", "--offline"])
    assert rc == 0, "public feeds are cached and fresh, so all must pass"
    # the internal feed has no cached copy here; had `all` included it,
    # fetch would have reported UNUSABLE and main would return 1
    assert not (cache / "product_definitions.json").exists()


def test_include_internal_opts_back_in(tmp_path):
    cache = _mk_cache(tmp_path)
    rc = ff.main(["--cache-dir", str(cache), "--feed", "all", "--include-internal", "--offline"])
    assert rc == 1, "internal feed has no cached copy and --offline"


def test_per_feed_max_age(tmp_path):
    assert ff.feed_max_age("epss") == ff.DEFAULT_MAX_AGE_HOURS
    # 24h matches upstream's own guidance to consumers; the prior 30 days
    # was justified on ids being immutable and ignored the contact half of
    # the payload, which changes about daily.
    assert ff.feed_max_age("product-definitions") == 24.0
    # an explicit --max-age-hours overrides every feed
    assert ff.feed_max_age("product-definitions", 5) == 5


def test_feed_status_uses_per_feed_thresholds(tmp_path):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    st = ff.feed_status(cache)
    assert st["epss"]["max_age_hours"] == ff.DEFAULT_MAX_AGE_HOURS
    assert st["product-definitions"]["max_age_hours"] == 24.0
    assert st["product-definitions"]["internal"] is True
    assert st["epss"]["internal"] is False


# ---------------- product-definitions loader shape guard ----------------


def _write_pd(cache, doc):
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "product_definitions.json").write_text(json.dumps(doc))


def test_load_product_definitions_happy(tmp_path):
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {"a": {}}, "ps_modules": {"a-1": {}}, "ps_update_streams": {}})
    doc = ff.load_product_definitions(cache)
    assert doc["ps_products"] == {"a": {}}


def test_load_product_definitions_raises_on_missing_key(tmp_path):
    """A silent upstream shape change must not read as 'no contacts'."""
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {}, "ps_update_streams": {}})
    try:
        ff.load_product_definitions(cache)
    except ValueError as e:
        assert "ps_modules" in str(e)
    else:
        raise AssertionError("missing ps_modules must raise")


def test_load_product_definitions_raises_on_wrong_type(tmp_path):
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {}, "ps_modules": [], "ps_update_streams": {}})
    try:
        ff.load_product_definitions(cache)
    except ValueError as e:
        assert "ps_modules" in str(e)
    else:
        raise AssertionError("a list where a map belongs must raise")


# ---------------- rh-cve: paginated + incremental ----------------


def _fake_pages(monkeypatch, pages):
    """Serve canned JSON pages, recording the query string of each call."""
    calls = []

    class _Resp:
        def __init__(self, body):
            self._b = body

        def read(self):
            return self._b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _open(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        calls.append(url)
        page = int(url.split("page=")[1].split("&")[0])
        body = json.dumps(pages[page - 1] if page <= len(pages) else [])
        return _Resp(body.encode())

    monkeypatch.setattr(ff.urllib.request, "urlopen", _open)
    return calls


def _rec(cve, date):
    return {
        "CVE": cve,
        "public_date": f"{date}T00:00:00Z",
        "bugzilla_description": f"comp-{cve[-1]}: comp-{cve[-1]}: title {cve}",
        "severity": "important",
        "cvss3_score": 7.5,
        "CWE": "CWE-863",
    }


def test_rh_cve_paginates_past_the_first_page(tmp_path, monkeypatch):
    """A window is not assumed to fit one page.

    Red Hat published 1000+ CVEs in one week against a weekly median of
    245, so stopping at page 1 would silently truncate the busiest weeks.
    """
    per = ff.FEEDS["rh-cve"]["paginate"]["per_page"]
    page1 = [_rec(f"CVE-2026-{i:05d}", "2026-06-01") for i in range(per)]
    page2 = [_rec("CVE-2026-99999", "2026-06-02")]
    calls = _fake_pages(monkeypatch, [page1, page2])
    cache = tmp_path / "feeds"
    ok, status = ff.fetch("rh-cve", cache, 24.0)
    assert ok, status
    recs = json.loads((cache / "rh_cve.json").read_text())
    assert len(recs) == per + 1
    assert len(calls) == 2, calls


def test_rh_cve_projects_and_merges_incrementally(tmp_path, monkeypatch):
    """Second run asks from the watermark and MERGES onto the cache.

    Overwriting would discard every earlier window — the whole point of
    an incremental feed is that history accumulates.
    """
    cache = tmp_path / "feeds"
    _fake_pages(monkeypatch, [[_rec("CVE-2026-00001", "2026-06-01")]])
    ff.fetch("rh-cve", cache, 24.0)
    meta = json.loads((cache / "feeds-meta.json").read_text())["rh-cve"]
    assert meta["watermark"] == "2026-06-01"
    assert meta["added_last_run"] == 1
    # projection: only the declared fields are stored
    rec = json.loads((cache / "rh_cve.json").read_text())[0]
    assert set(rec) == set(ff.FEEDS["rh-cve"]["project"])

    calls = _fake_pages(monkeypatch, [[_rec("CVE-2026-00002", "2026-06-05")]])
    ff.fetch("rh-cve", cache, 0.0)  # force refresh
    assert "after=2026-06-01" in calls[0], calls[0]
    recs = json.loads((cache / "rh_cve.json").read_text())
    assert {r["CVE"] for r in recs} == {"CVE-2026-00001", "CVE-2026-00002"}
    meta = json.loads((cache / "feeds-meta.json").read_text())["rh-cve"]
    assert meta["watermark"] == "2026-06-05" and meta["added_last_run"] == 1


def test_rh_cve_backfills_from_campaign_start_when_no_watermark(tmp_path, monkeypatch):
    calls = _fake_pages(monkeypatch, [[_rec("CVE-2026-00001", "2026-06-01")]])
    ff.fetch("rh-cve", tmp_path / "feeds", 24.0)
    assert f"after={ff.FEEDS['rh-cve']['incremental']['backfill_from']}" in calls[0]


def test_rh_cve_page_cap_refuses_to_loop(tmp_path, monkeypatch):
    per = ff.FEEDS["rh-cve"]["paginate"]["per_page"]
    full = [_rec(f"CVE-2026-{i:05d}", "2026-06-01") for i in range(per)]
    _fake_pages(monkeypatch, [full] * (ff.MAX_FEED_PAGES + 2))
    ok, status = ff.fetch("rh-cve", tmp_path / "feeds", 24.0)
    assert not ok and "no cached copy" in status


def test_load_rh_cves_splits_component_and_title(tmp_path):
    cache = tmp_path / "feeds"
    cache.mkdir()
    (cache / "rh_cve.json").write_text(
        json.dumps(
            [
                {
                    "CVE": "CVE-2026-66792",
                    "public_date": "2026-08-17T17:25:00Z",
                    "bugzilla_description": (
                        "multicloud-operators-subscription: "
                        "multicloud-operators-subscription: "
                        "IsClusterAdmin() trusts user-settable annotations"
                    ),
                    "severity": "important",
                    "cvss3_score": 9.9,
                    "CWE": "CWE-863",
                }
            ]
        )
    )
    got = ff.load_rh_cves(cache)["CVE-2026-66792"]
    assert got["component"] == "multicloud-operators-subscription"
    # the doubled component echo is stripped, not left in the title
    assert got["title"] == "IsClusterAdmin() trusts user-settable annotations"
    assert got["public_date"] == "2026-08-17" and got["cvss3"] == 9.9


def test_rh_cve_is_watched_by_drift(tmp_path, monkeypatch):
    """A new feed must not go silently unmonitored."""
    from traust.cli.check_drift import check_feeds
    from traust.context import load_engine

    cache = tmp_path / "drift-cache"
    cache.mkdir()
    (cache / "feeds-meta.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("FEEDS_CACHE_DIR", str(cache))
    rows = {row["item"]: row for row in check_feeds(load_engine())}
    assert rows["feeds:rh-cve"]["status"] == "unavailable"


def test_explicit_config_home_controls_feed_validation_and_fetch(tmp_path, monkeypatch):
    from traust.context import load_engine

    homes = {}
    for name in ("alpha", "beta"):
        home = tmp_path / name
        shutil.copytree(os.environ["TRAUST_CONFIG_HOME"], home)
        registry = yaml.safe_load((home / "feeds.yaml").read_text())
        spec = dict(registry["sources"]["kev"])
        spec.update(file=f"{name}.json", internal=False)
        registry["sources"] = {name: spec}
        (home / "feeds.yaml").write_text(yaml.safe_dump(registry), encoding="utf-8")
        loc_path = home / "locations.yaml"
        loc = yaml.safe_load(loc_path.read_text())
        loc["product_definitions"] = f"https://{name}.test/products.json"
        loc_path.write_text(yaml.safe_dump(loc), encoding="utf-8")
        homes[name] = home
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(homes["alpha"]))
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "alpha.json").write_text("{}\n")
    (cache / "beta.json").write_text("{}\n")
    assert "alpha" in ff._feeds()
    assert "beta" not in ff._feeds()
    assert (
        ff.main(
            [
                "--config-home",
                str(homes["beta"]),
                "--cache-dir",
                str(cache),
                "--feed",
                "beta",
                "--offline",
            ]
        )
        == 0
    )
    assert ff._feeds()["beta"]["file"] == "beta.json"
    assert ff._feeds()["product-definitions"]["url"] == "https://beta.test/products.json"
    assert "alpha" not in ff._feeds()
    alpha_registry = ff.feed_registry(load_engine(homes["alpha"]))
    assert set(alpha_registry) == {"alpha", "product-definitions"}
    assert alpha_registry["alpha"]["file"] == "alpha.json"
    assert alpha_registry["product-definitions"]["url"] == "https://alpha.test/products.json"
    # Reading another engine's registry must not alter the fetcher's selection.
    assert "beta" in ff._feeds()
    assert "alpha" not in ff._feeds()
    with pytest.raises(SystemExit) as exc:
        ff.main(["--config-home", str(homes["beta"]), "--feed", "alpha", "--offline"])
    assert exc.value.code == 2
    # A second invocation must not retain the previous run's registry.
    assert (
        ff.main(
            [
                "--cache-dir",
                str(cache),
                "--feed",
                "alpha",
                "--offline",
            ]
        )
        == 0
    )
    assert "beta" not in ff._feeds()
    # Successive explicit homes must also select the new home's payload and URL.
    assert (
        ff.main(
            [
                "--config-home",
                str(homes["beta"]),
                "--cache-dir",
                str(cache),
                "--feed",
                "beta",
                "--offline",
            ]
        )
        == 0
    )
    assert ff._feeds()["beta"]["file"] == "beta.json"
    assert ff._feeds()["product-definitions"]["url"] == "https://beta.test/products.json"
