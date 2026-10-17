"""Tests for traust.cli.fetch_feeds + enrich_findings_cves.py (C8)."""

import gzip
import json
import sys
from pathlib import Path

import pytest
from traust_contracts import Locations
from traust_core.v1.errors import ServiceError
from traust_core.v1.providers.http import HttpFetcher

from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]


def _fake_get(monkeypatch, outcome):
    """Stub core's HttpFetcher.get: return ``outcome`` bytes or raise it."""

    def _get(self, url):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(HttpFetcher, "get", _get)


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
def _product_definitions_configured(monkeypatch):
    """product-definitions is config-gated (locations.product_definitions) since it
    targets a deployment-specific registry. The suite exercises it as a configured
    estate would; the lazy feeds cache is reset so the gate is re-evaluated per
    test. Tests that want the open-source default (absent) override it."""
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
    _fake_get(monkeypatch, AssertionError("network touched"))
    usable, status = ff.fetch("epss", cache, 24)
    assert usable and status.startswith("fresh")


def test_failed_refresh_falls_back(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    _fake_get(monkeypatch, ServiceError("no vpn"))
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

    def _get(self, url):
        calls.append(url)
        page = int(url.split("page=")[1].split("&")[0])
        return json.dumps(pages[page - 1] if page <= len(pages) else []).encode()

    monkeypatch.setattr(HttpFetcher, "get", _get)
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


def test_rh_cve_is_watched_by_drift():
    """A new feed must not go silently unmonitored."""
    from traust.cli.check_drift import watched_feeds

    assert ("rh-cve", False) in watched_feeds()


# ---------------- retry / stale (XWING-2223) ----------------
# Retry/backoff behaviour is tested in traust-core (providers/test_http.py);
# these cover what fetch_feeds does with the outcome.


def test_shipped_retry_config_builds_core_policy():
    from traust_core.v1.providers.http import RetryPolicy

    from traust.registry.feeds_config import retry_defaults

    shipped = retry_defaults(_ROOT / "config" / "feeds.yaml")
    assert (
        RetryPolicy(**shipped).max_attempts == shipped["max_attempts"]
    )  # unknown key -> TypeError


def test_stale_fallback_records_last_error(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    _fake_get(monkeypatch, ServiceError("http://feed.test: gave up after 4 attempts (no vpn)"))
    usable, status = ff.fetch("epss", cache, 24)
    assert usable and "STALE" in status
    meta = json.loads((cache / "feeds-meta.json").read_text())["epss"]
    assert meta["stale"] is True
    assert "no vpn" in meta["last_error"]
    assert meta["last_attempt_at"]


def test_corrupt_download_keeps_old_copy(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    good = (cache / "epss_scores-current.csv.gz").read_bytes()
    _fake_get(monkeypatch, b"not a gzip payload")
    usable, status = ff.fetch("epss", cache, 24)
    assert usable and "STALE" in status  # corrupt refresh falls back, never unusable here
    assert (cache / "epss_scores-current.csv.gz").read_bytes() == good  # cache not overwritten
    meta = json.loads((cache / "feeds-meta.json").read_text())["epss"]
    assert meta["stale"] is True and "corrupt" in meta["last_error"]
