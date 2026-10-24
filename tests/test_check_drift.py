"""Tests for traust.cli.check_drift — staleness & drift checker."""

import datetime
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[1]
from traust.cli import check_drift as cd
from traust.context import load_engine
from traust.paths import skill_dir

_needs_operational_config = pytest.mark.skipif(
    __import__("traust_contracts", fromlist=["deployment_config_dir"]).deployment_config_dir()
    is None,
    reason="ref-provenance reads $TRAUST_CONFIG_HOME/corpus-config.yaml; no operational config here",
)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _mk_ws(tmp_path):
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "feeds").mkdir(parents=True)
    (ws / "progress-tracker" / "feeds").mkdir(parents=True)
    (ws / "analysis-results" / "graph").mkdir(parents=True)
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    (ws / "progress-tracker" / "metrics").mkdir(parents=True)
    return ws


@pytest.fixture(autouse=True)
def _private_config_home(tmp_path, monkeypatch):
    """Each test gets its own copy of the suite's config home.

    Deployment config (adr-registry, sla-policy, org-parameters, the
    reachability watch register) is read from the config home, so a test that
    seeds one must not leak it into the shared suite home.
    """
    home = tmp_path / "config-home"
    shutil.copytree(os.environ["TRAUST_CONFIG_HOME"], home)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    return home


def _home() -> Path:
    return Path(os.environ["TRAUST_CONFIG_HOME"])


def _engine_for_ws(tmp_path, ws, monkeypatch):
    home = tmp_path / "cfg"
    home.mkdir(exist_ok=True)
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "workspace": str(ws),
                "analysis_results": str(ws / "analysis-results"),
                "progress_tracker": str(ws / "progress-tracker"),
            }
        ),
        encoding="utf-8",
    )
    fixture = Path(__file__).parent / "fixtures" / "config"
    for name in fixture.iterdir():
        if name.is_file():
            shutil.copy2(name, home / name.name)
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    return load_engine()


@pytest.fixture(autouse=True)
def _product_definitions_configured(monkeypatch):
    """product-definitions is the canonical optional/internal feed these tests
    exercise; it is config-gated (locations.product_definitions) since it targets
    a deployment-specific registry."""
    from traust_contracts import Locations

    from traust.cli import fetch_feeds as _ff

    monkeypatch.setattr(
        _ff.locations,
        "configured_locations",
        lambda: Locations(product_definitions="https://feeds.test/product-definitions.json"),
    )


def _feed(name, status="fresh", refresh=None, kind="feeds"):
    from traust_core.v1.models.operations import Freshness, StaleItem

    return StaleItem(item=f"{kind}:{name}", status=Freshness(status), detail="d", refresh=refresh)


def test_feeds_fresh_and_stale(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    statuses = [_feed("epss"), _feed("kev", "stale", "fetch feed kev")]
    items = {
        i["item"]: i for i in cd.check_feeds(_engine_for_ws(tmp_path, ws, monkeypatch), statuses)
    }
    assert items["feeds:epss"]["status"] == "fresh"
    assert "refresh" not in items["feeds:epss"]
    assert items["feeds:kev"]["status"] == "stale"
    assert items["feeds:kev"]["refresh"] == "fetch feed kev"


def test_feeds_absent_is_pending(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    engine = _engine_for_ws(tmp_path, ws, monkeypatch)
    assert cd.check_feeds(engine, [_feed("epss", "pending")])[0]["status"] == "pending"


def test_core_freshness_rows_pass_through_but_tool_databases(tmp_path, monkeypatch):
    """The grype-db / external-tools rows check the tools until the engine wires core's
    ToolInspector, so core's `tool-databases: unavailable` row is not repeated."""
    from traust_contracts import Locations

    from traust.cli import fetch_feeds as _ff

    monkeypatch.setattr(_ff.locations, "configured_locations", lambda: Locations())
    ws = _mk_ws(tmp_path)
    from traust_core.v1.models.operations import Freshness, StaleItem

    databases = StaleItem(item="tool-databases", status=Freshness.UNAVAILABLE, detail="NEED")
    rows = [_feed("epss"), _feed("kev", kind="feed"), databases]
    items = cd.check_feeds(_engine_for_ws(tmp_path, ws, monkeypatch), rows)
    assert [i["item"] for i in items] == ["feeds:epss", "feed:kev"]


def test_optional_feed_never_fetched_is_pending_not_unavailable(tmp_path, monkeypatch):
    """A VPN-only feed nobody has fetched is a normal state.

    Reporting `unavailable` would put an optional source in the same
    bucket as a broken one and pull it into --fail-on.
    """
    ws = _mk_ws(tmp_path)
    monkeypatch.setenv("FEEDS_CACHE_DIR", str(ws / "progress-tracker/feeds"))
    statuses = [_feed("epss"), _feed("kev")]
    items = {
        i["item"]: i for i in cd.check_feeds(_engine_for_ws(tmp_path, ws, monkeypatch), statuses)
    }
    pd_item = items["registry:product-definitions"]
    assert pd_item["status"] == "pending"
    assert pd_item["refresh"] == "traust feeds fetch-products"


def test_optional_feed_uses_its_own_threshold(tmp_path, monkeypatch):
    """7 days for the VPN-only optional feed; epss/kev rows are core's (their own max age)."""
    ws = _mk_ws(tmp_path)
    monkeypatch.setenv("FEEDS_CACHE_DIR", str(ws / "progress-tracker/feeds"))
    now = cd._now()
    ten_days = now - datetime.timedelta(days=3)
    (ws / "progress-tracker/feeds/feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": _iso(ten_days)}})
    )
    engine = _engine_for_ws(tmp_path, ws, monkeypatch)
    items = {i["item"]: i for i in cd.check_feeds(engine, [_feed("epss", "stale"), _feed("kev")])}
    assert items["feeds:epss"]["status"] == "stale"
    assert items["registry:product-definitions"]["status"] == "fresh"

    forty_days = now - datetime.timedelta(days=40)
    (ws / "progress-tracker/feeds/feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": _iso(forty_days)}})
    )
    items = {i["item"]: i for i in cd.check_feeds(engine, [_feed("epss")])}
    assert items["registry:product-definitions"]["status"] == "stale"
    assert items["registry:product-definitions"]["refresh"] == "traust feeds fetch-products"


def test_unconfigured_product_definitions_has_no_row(tmp_path, monkeypatch):
    from traust_contracts import Locations

    from traust.cli import fetch_feeds as _ff

    monkeypatch.setattr(_ff.locations, "configured_locations", lambda: Locations())
    ws = _mk_ws(tmp_path)
    items = cd.check_feeds(_engine_for_ws(tmp_path, ws, monkeypatch), [_feed("epss")])
    assert [i["item"] for i in items] == ["feeds:epss"]


def test_rule_mining_pending_fresh_stale(tmp_path):
    import os

    ws = _mk_ws(tmp_path)
    art = ws / "progress-tracker/metrics/rule-mining" / "rule-mining.json"
    # pending: artifact not built yet
    res = cd.check_rule_mining(ws)[0]
    assert res["status"] == "pending"
    assert "traust.cli sweep rule-lane" in res["refresh"]
    # unavailable: artifact exists but no ledgers anywhere
    art.parent.mkdir(parents=True)
    art.write_text("{}")
    assert cd.check_rule_mining(ws)[0]["status"] == "unavailable"
    # fresh (grace window): ledger changed after the mine, but inside
    # RULE_MINING_LAG_DAYS
    ledger = ws / "analysis-results/findings/p" / "r-findings-layer.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_text("{}")
    two_days_ago = (cd._now() - datetime.timedelta(days=2)).timestamp()
    os.utime(art, (two_days_ago, two_days_ago))
    res = cd.check_rule_mining(ws)[0]
    assert res["status"] == "fresh"
    assert "weekly-lane window" in res["detail"]
    # stale: ledger changes are > RULE_MINING_LAG_DAYS newer than the
    # artifact — the post-wave trigger
    long_ago = (cd._now() - datetime.timedelta(days=cd.RULE_MINING_LAG_DAYS + 3)).timestamp()
    os.utime(art, (long_ago, long_ago))
    res = cd.check_rule_mining(ws)[0]
    assert res["status"] == "stale"
    assert "traust.cli sweep rule-lane" in res["refresh"]
    # fresh: artifact newer than every ledger event
    now = cd._now().timestamp()
    os.utime(art, (now, now))
    assert cd.check_rule_mining(ws)[0]["status"] == "fresh"


@pytest.mark.requires_git
def test_repo_graph_stale_when_inputs_move(tmp_path):
    ws = _mk_ws(tmp_path)
    inputs = ws / "inputs"
    inputs.mkdir()
    subprocess.run(["git", "init", "-q", str(inputs)], check=True)
    (inputs / "x.csv").write_text("a\n")
    subprocess.run(
        ["git", "-C", str(inputs), "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(inputs),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "x",
        ],
        check=True,
    )
    # graph "generated" long before the inputs commit
    (ws / "analysis-results/graph/repo-graph.json").write_text(
        json.dumps({"generated": "2020-01-01", "nodes": [], "edges": []})
    )
    items = {i["item"]: i for i in cd.check_graphs(ws)}
    assert items["repo-graph"]["status"] == "stale"
    assert "inputs" in items["repo-graph"]["detail"]
    assert items["portfolio-graph"]["status"] == "pending"


def test_adr_registry_pending_then_checked(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    assert cd.check_adr_registry(ws)[0]["status"] == "pending"
    (_home() / "adr-registry.yaml").write_text(
        "registers:\n  - {name: arch, repo: https://x/y.git, pin: aaaa1111}\n"
    )
    monkeypatch.setattr(
        cd.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "bbbb2222\tHEAD\n"})()
    )
    res = cd.check_adr_registry(ws)[0]
    assert res["status"] == "stale"
    assert "superseded" in res["detail"]
    monkeypatch.setattr(
        cd.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "aaaa1111ffff\tHEAD\n"})()
    )
    assert cd.check_adr_registry(ws)[0]["status"] == "fresh"


def test_provenance_review_due(tmp_path):
    pytest.importorskip("yaml")
    ws = _mk_ws(tmp_path)
    (_home() / "sla-policy.yaml").write_text("source: {retrieved: '2020-01-01'}\n")
    items = {i["item"]: i for i in cd.check_policy_provenance(ws)}
    assert items["provenance:sla-policy"]["status"] == "review_due"


def _core_snapshots(tmp_path, ages):
    """Feed snapshots in a core store under the test's config home, `ages` hours old."""
    from traust_core.v1.providers.base import Acquisition, Readiness, Result

    from traust.context import load_core

    (_home() / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    core = load_core(_home())

    class Feed:
        filename, max_age = "payload.json", datetime.timedelta(hours=24)

        def __init__(self, name, hours):
            self.name, self.at = name, cd._now() - datetime.timedelta(hours=hours)

        def check(self):
            return Readiness(ready=True)

        def fetch(self, previous=lambda: None):
            return Result(b"{}", Acquisition(provider=self.name, acquired_at=self.at))

    for name, hours in ages.items():
        feed = Feed(name, hours)
        core.feeds.register(name, lambda feed=feed: feed)
    core.services().exposure.refresh_feeds()


def test_main_writes_report_and_fail_on(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    _core_snapshots(tmp_path, {"epss": 0, "kev": 999})
    rc = cd.main(["--workspace", str(ws)])
    assert rc == 0
    report = json.loads((ws / "progress-tracker/metrics/drift/drift-report.json").read_text())
    assert report["metadata"]["artifact"] == "staleness-drift-report"
    assert report["summary"].get("stale", 0) >= 1
    rows = {i["item"]: i["status"] for i in report["items"]}
    assert (rows["feeds:epss"], rows["feeds:kev"]) == ("fresh", "stale")
    assert {f"feeds:{n}" for n in ("rh-cve", "vex")} <= set(rows)
    md = (ws / "progress-tracker/metrics/drift/drift-report.md").read_text()
    assert "Refresh queue" in md and "never concludes" in md
    assert cd.main(["--workspace", str(ws), "--fail-on", "stale"]) == 1
    # drift-only gate: stale items alone don't trip it
    assert cd.main(["--workspace", str(ws), "--fail-on", "drift"]) in (
        0,
        1,
    )  # corpus check may report unavailable, never drift here


def test_checker_error_never_kills_run(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)

    def boom(_ws):
        raise RuntimeError("kaput")

    monkeypatch.setattr(cd, "CHECKS", (boom,))
    monkeypatch.setattr(cd, "check_feeds", lambda _engine, _statuses: [])
    rc = cd.main(["--workspace", str(ws)])
    assert rc == 0
    report = json.loads((ws / "progress-tracker/metrics/drift/drift-report.json").read_text())
    assert any(i["item"] == "boom" and i["status"] == "unavailable" for i in report["items"])


def test_framework_upstream_pin_check(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    comp = tmp_path / "compliance-data"
    comp.mkdir()
    monkeypatch.setattr(cd, "_compliance_data", lambda: comp)
    assert cd.check_framework_upstream(ws)[0]["status"] == "pending"
    (comp / "provenance.json").write_text(
        json.dumps({"upstream": "https://x/y", "upstream_head": "aaaa1111"})
    )
    monkeypatch.setattr(
        cd.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "bbbb2222\tHEAD\n"})()
    )
    res = cd.check_framework_upstream(ws)[0]
    assert res["status"] == "stale" and "re-deriv" in res["refresh"]
    monkeypatch.setattr(
        cd.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "aaaa1111ff\tHEAD\n"})()
    )
    assert cd.check_framework_upstream(ws)[0]["status"] == "fresh"


def test_catalog_reviewed_dates_covered(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    ws = _mk_ws(tmp_path)
    comp = tmp_path / "compliance-data"
    comp.mkdir()
    monkeypatch.setattr(cd, "_compliance_data", lambda: comp)
    (comp / "catalog-pci-dss-v4.yaml").write_text("reviewed: '2020-01-01'\nframework: pci-dss-v4\n")
    items = {i["item"]: i for i in cd.check_policy_provenance(ws)}
    assert items["provenance:catalog-pci-dss"]["status"] == "review_due"
    assert items["provenance:catalog-soc2-tsc"]["status"] == "pending"


def _facts_doc(adapter=None, commit=None, path_class="first_party"):
    import re

    src = (skill_dir("pqc-readiness") / "scripts" / "pqc_facts.py").read_text()
    cur_commit = re.search(r'PQC_SCAN_COMMIT\s*=\s*"([^"]+)"', src)
    cur_adapter = re.search(r'ADAPTER_VERSION\s*=\s*\(?\s*"([^"]+)"', src)
    return {
        "artifact": "pqc-facts",
        "repository": "https://github.com/example/repo",
        "stamps": {
            "adapter_version": adapter or (cur_adapter.group(1) if cur_adapter else "x"),
            "pqc_scan_commit": commit or (cur_commit.group(1) if cur_commit else "x"),
            "rules_sha256": "r" * 64,
            "binary_sha256": "b" * 64,
        },
        "coverage": {
            "assessment_basis": "source",
            "scanned_files": 10,
            "skipped_files": 0,
            "rules_in_pack": 130,
        },
        "summary": {"by_rule": {}, "by_qclass": {}, "by_provenance_hint": {}, "by_path_class": {}},
        "facts": [
            {
                "fact_id": "F0000",
                "rule_id": "HP_TEST_RULE",
                "file": "main.go",
                "line": 1,
                "detail": "d",
                "provenance_hint": "native",
                "path_class": path_class,
                "ir8547": {"qclass": "shor_128bit_plus", "usage": "tls", "clock": None},
            }
        ],
    }


def _write_facts(ws, slug, doc):
    d = ws / "analysis-results" / "pqc" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{slug}-pqc-facts.json").write_text(json.dumps(doc, indent=1))


def test_pqc_facts_stamps_fresh_and_stale(tmp_path):
    ws = _mk_ws(tmp_path)
    _write_facts(ws, "current", _facts_doc())
    items = {i["item"]: i for i in cd.check_pqc_facts_provenance(ws)}
    assert items["pqc-facts-stamps"]["status"] == "fresh"
    _write_facts(ws, "old-adapter", _facts_doc(adapter="0.9.0"))
    _write_facts(ws, "old-scanner", _facts_doc(commit="deadbeef" * 5))
    items = {i["item"]: i for i in cd.check_pqc_facts_provenance(ws)}
    assert items["pqc-facts-stamps"]["status"] == "stale"
    assert "0.9.0" in items["pqc-facts-stamps"]["detail"]
    assert "re-run /pqc-readiness" in items["pqc-facts-stamps"]["refresh"]


def test_pqc_facts_schema_sample_drift(tmp_path):
    pytest.importorskip("jsonschema")
    ws = _mk_ws(tmp_path)
    _write_facts(ws, "good", _facts_doc())
    items = {i["item"]: i for i in cd.check_pqc_facts_provenance(ws)}
    assert items["pqc-facts-schema"]["status"] == "fresh"
    _write_facts(ws, "bad", _facts_doc(path_class="third_party"))
    items = {i["item"]: i for i in cd.check_pqc_facts_provenance(ws)}
    assert items["pqc-facts-schema"]["status"] == "drift"
    assert "bad" in items["pqc-facts-schema"]["detail"]


def test_pqc_facts_absent_corpus_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    assert cd.check_pqc_facts_provenance(ws)[0]["status"] == "pending"


def _dash(ws, rel, generated, rows=()):
    p = ws / "progress-tracker" / "metrics" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    body = f"# Dash\n\n**Generated:** {generated}\n\n"
    for r in rows:
        body += f"| {r} | claude-mythos-5 | 1 | 1 | 1 | 1 | 1 | 1.00 |\n"
    p.write_text(body)
    return p


def test_dashboard_staleness_fresh_and_stale(tmp_path):
    ws = _mk_ws(tmp_path)
    today = cd._now().date().isoformat()
    old = (cd._now() - datetime.timedelta(days=30)).date().isoformat()
    _dash(ws, "traust-metrics.md", old)
    _dash(ws, "dashboards/spend/spend-dashboard.md", today, rows=[today])
    items = {i["item"]: i for i in cd.check_dashboard_staleness(ws)}
    assert items["dashboards:harness-scoreboard"]["status"] == "stale"
    assert "collect_harness_metrics" in (items["dashboards:harness-scoreboard"]["refresh"])
    assert items["dashboards:spend"]["status"] == "fresh"
    assert items["dashboards:spend-actuals"]["status"] == "fresh"
    # dependency-exposure not built yet -> pending (never crashes)
    assert items["dashboards:dependency-exposure"]["status"] == "pending"


def test_dashboard_staleness_dependency_exposure_fresh(tmp_path):
    ws = _mk_ws(tmp_path)
    today = cd._now().date().isoformat()
    _dash(ws, "dependency-exposure/dependency-exposure.md", today)
    items = {i["item"]: i for i in cd.check_dashboard_staleness(ws)}
    assert items["dashboards:dependency-exposure"]["status"] == "fresh"
    old = (cd._now() - datetime.timedelta(days=20)).date().isoformat()
    _dash(ws, "dependency-exposure/dependency-exposure.md", old)
    items = {i["item"]: i for i in cd.check_dashboard_staleness(ws)}
    assert items["dashboards:dependency-exposure"]["status"] == "stale"
    assert "dependency-exposure" in (items["dashboards:dependency-exposure"]["refresh"])


def test_dashboard_staleness_stale_actuals_behind_fresh_stamp(tmp_path):
    # rebuilt dashboard (fresh stamp) but nobody appended actuals
    ws = _mk_ws(tmp_path)
    today = cd._now().date().isoformat()
    old = (cd._now() - datetime.timedelta(days=10)).date().isoformat()
    _dash(ws, "dashboards/spend/spend-dashboard.md", today, rows=[old])
    items = {i["item"]: i for i in cd.check_dashboard_staleness(ws)}
    assert items["dashboards:spend"]["status"] == "fresh"
    assert items["dashboards:spend-actuals"]["status"] == "stale"
    assert "traust.cli metrics collect-spend" in (items["dashboards:spend-actuals"]["refresh"])


def test_dashboard_staleness_absent_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    items = {i["item"]: i for i in cd.check_dashboard_staleness(ws)}
    assert items["dashboards:harness-scoreboard"]["status"] == "pending"
    assert items["dashboards:spend"]["status"] == "pending"


def test_rescan_worklist_missing_is_stale(tmp_path):
    # a missing worklist means the daily router loop is not running —
    # stale (actionable), not pending
    ws = _mk_ws(tmp_path)
    (ws / "analysis-results/findings/_manifest").mkdir(parents=True)
    items = cd.check_rescan_worklist(ws)
    assert items[0]["status"] == "stale"
    assert "build_rescan_worklist" in items[0]["refresh"]


def test_rescan_worklist_fresh_and_stale(tmp_path):
    ws = _mk_ws(tmp_path)
    man = ws / "analysis-results/findings/_manifest"
    man.mkdir(parents=True)
    wl = man / "rescan-worklist.json"
    wl.write_text(json.dumps({"generated_at": _iso(cd._now())}))
    assert cd.check_rescan_worklist(ws)[0]["status"] == "fresh"
    wl.write_text(json.dumps({"generated_at": _iso(cd._now() - datetime.timedelta(days=4))}))
    items = cd.check_rescan_worklist(ws)
    assert items[0]["status"] == "stale"
    assert "build_rescan_worklist" in items[0]["refresh"]


def test_rescan_worklist_unparseable_is_unavailable(tmp_path):
    ws = _mk_ws(tmp_path)
    man = ws / "analysis-results/findings/_manifest"
    man.mkdir(parents=True)
    (man / "rescan-worklist.json").write_text("junk")
    assert cd.check_rescan_worklist(ws)[0]["status"] == "unavailable"


def _patch_tools(
    monkeypatch,
    *,
    which=True,
    local="1.0.0",
    upstream=("1.0.0", None),
    expected=None,
    adopter=False,
):
    monkeypatch.setattr(
        cd,
        "EXTERNAL_TOOLS",
        [
            {
                "name": "fakescan",
                "argv": ["fakescan", "--version"],
                "kind": "github",
                "ref": "example/fakescan",
                "version_re": cd._SEMVER_RE,
                "expected": expected,
                "adopter": adopter,
            }
        ],
    )
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/fakescan" if which else None)
    monkeypatch.setattr(cd, "_installed_tool_version", lambda *a: local)
    monkeypatch.setattr(cd, "_latest_upstream", lambda *_: upstream)


def test_external_tools_missing_is_pending(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, which=False)
    items = cd.check_external_tools(_mk_ws(tmp_path))
    assert items[0]["item"] == "external-tools:fakescan"
    assert items[0]["status"] == "pending"


def test_an_absent_adopter_tool_is_not_pending_and_its_pin_is_checked(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, which=False, adopter=True, expected="2.7.0", upstream=("2.7.0", None))
    row = cd.check_external_tools(_mk_ws(tmp_path))[0]
    assert row["status"] == "fresh"
    assert "adopter-provided" in row["detail"]


def test_an_adopter_tool_pin_behind_upstream_is_stale(tmp_path, monkeypatch):
    old = cd._now() - datetime.timedelta(days=cd.EXTERNAL_TOOL_LAG_GRACE_DAYS + 10)
    _patch_tools(monkeypatch, which=False, adopter=True, expected="2.4.0", upstream=("2.7.0", old))
    row = cd.check_external_tools(_mk_ws(tmp_path))[0]
    assert row["status"] == "stale"
    assert "advance `expected`" in row["refresh"]


def test_an_installed_adopter_tool_is_checked_like_any_other(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, adopter=True, local="2.4.0", expected="2.7.0")
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "drift"


def test_the_shipped_osv_scanner_row_is_adopter_provided_and_in_no_profile():
    import yaml

    rows = yaml.safe_load((cd.HARNESS_ROOT / "config" / "external-tools.yaml").read_text())
    osv = next(t for t in rows["tools"] if t["name"] == "osv-scanner")
    assert osv["provided_by"] == "adopter"
    assert osv["consumers"] == []


def test_external_tools_current_is_fresh(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, local="2.1.0", upstream=("2.1.0", None))
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "fresh"


def test_external_tools_lag_past_grace_is_stale(tmp_path, monkeypatch):
    old = cd._now() - datetime.timedelta(days=cd.EXTERNAL_TOOL_LAG_GRACE_DAYS + 10)
    _patch_tools(monkeypatch, local="2.0.0", upstream=("2.1.0", old))
    items = cd.check_external_tools(_mk_ws(tmp_path))
    assert items[0]["status"] == "stale"
    assert "release notes" in items[0]["refresh"]


def test_external_tools_lag_within_grace_is_fresh(tmp_path, monkeypatch):
    recent = cd._now() - datetime.timedelta(days=2)
    _patch_tools(monkeypatch, local="2.0.0", upstream=("2.1.0", recent))
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "fresh"


def test_external_tools_lag_unknown_date_is_stale(tmp_path, monkeypatch):
    # no published date -> cannot apply grace, err on the loud side
    _patch_tools(monkeypatch, local="2.0.0", upstream=("2.1.0", None))
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "stale"


def test_external_tools_upstream_unreachable_is_unavailable(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, local="2.0.0", upstream=None)
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "unavailable"


def test_external_tools_version_unparseable_is_unavailable(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, local=None)
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "unavailable"


def test_external_tools_unstamped_zero_version_is_unavailable(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, local="0.0.0", upstream=("1.6.0", None))
    items = cd.check_external_tools(_mk_ws(tmp_path))
    assert items[0]["status"] == "unavailable"
    assert "unstamped" in items[0]["detail"]


def test_external_tools_below_expected_floor_is_drift(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, local="1.9.0", upstream=("2.1.0", None), expected="2.0.0")
    items = cd.check_external_tools(_mk_ws(tmp_path))
    assert items[0]["status"] == "drift"
    assert "external-tools.yaml" in items[0]["refresh"]


def test_external_tools_at_expected_floor_checks_upstream(tmp_path, monkeypatch):
    _patch_tools(monkeypatch, local="2.0.0", upstream=("2.0.0", None), expected="2.0.0")
    assert cd.check_external_tools(_mk_ws(tmp_path))[0]["status"] == "fresh"


def test_external_tools_manifest_loads_real_file():
    tools, err = cd._load_external_tools()
    assert err is None
    names = {t["name"] for t in tools}
    assert {"opengrep", "gitleaks", "govulncheck"} <= names
    gv = next(t for t in tools if t["name"] == "govulncheck")
    assert "govulncheck@v" in gv["version_re"]
    assert all(t["expected"] for t in tools)


def test_external_tools_missing_manifest_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(cd, "EXTERNAL_TOOLS_MANIFEST", tmp_path / "nope.yaml")
    items = cd.check_external_tools(_mk_ws(tmp_path))
    assert items[0]["status"] == "unavailable"
    assert "missing" in items[0]["detail"]


def test_external_tools_malformed_entry_fails_whole_load(monkeypatch, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("tools:\n  - name: x\n")  # no version_cmd/upstream
    monkeypatch.setattr(cd, "EXTERNAL_TOOLS_MANIFEST", bad)
    tools, err = cd._load_external_tools()
    assert tools is None and "malformed" in err


# --- P1 gate rework: version_cmd allowlist (rollup-F2) -------------------


def test_version_cmd_rejects_unlisted_binary():
    assert cd._vet_version_cmd(["python3", "-c", "print(1)"])


def test_version_cmd_rejects_path_head():
    assert cd._vet_version_cmd(["/usr/bin/syft", "--version"])


def test_version_cmd_rejects_non_flag_arg():
    assert cd._vet_version_cmd(["syft", "/etc/passwd"])


def test_version_cmd_accepts_known_probes():
    for argv in (["syft", "--version"], ["gitleaks", "version"], ["govulncheck", "-version"]):
        assert cd._vet_version_cmd(argv) is None


# --- language-coverage: the anti-Go-bias tripwire ------------------------


def _write_lang_cache(ws, records):
    p = (
        ws
        / "analysis-results"
        / "findings"
        / "_manifest"
        / "portfolio-lang"
        / "gh-languages-cache-merged.jsonl"
    )
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p


def test_language_coverage_cache_absent_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    assert cd.check_language_coverage(ws)[0]["status"] == "pending"


def test_language_coverage_flags_uncovered_dominant_language(tmp_path):
    """An uncovered language dominant at the threshold flags; a covered
    language (Python->pypi) and allowlisted ones (Shell, YAML) do not."""
    ws = _mk_ws(tmp_path)
    records = []
    # Swift dominant in exactly THRESHOLD repos, uncovered -> flag
    for i in range(cd.LANGUAGE_COVERAGE_THRESHOLD):
        records.append({"repo": f"org/swift{i}", "languages": {"Swift": 5000, "Shell": 100}})
    # Python dominant, covered via pypi -> no flag
    for i in range(cd.LANGUAGE_COVERAGE_THRESHOLD + 2):
        records.append({"repo": f"org/py{i}", "languages": {"Python": 9000, "Makefile": 10}})
    # Shell dominant, allowlisted -> no flag
    for i in range(cd.LANGUAGE_COVERAGE_THRESHOLD + 1):
        records.append({"repo": f"org/sh{i}", "languages": {"Shell": 9000, "YAML": 100}})
    _write_lang_cache(ws, records)
    items = {i["item"]: i for i in cd.check_language_coverage(ws)}
    assert items["language-coverage:Swift"]["status"] == "drift"
    assert "Swift" in items["language-coverage:Swift"]["detail"]
    assert "allowlist" in items["language-coverage:Swift"]["detail"]
    assert "language-coverage:Python" not in items
    assert "language-coverage:Shell" not in items
    assert "language-coverage:YAML" not in items


def test_language_coverage_threshold_boundary_no_flag(tmp_path):
    """Exactly THRESHOLD-1 dominant repos for an uncovered language must
    NOT flag; the summary fresh row is emitted instead."""
    ws = _mk_ws(tmp_path)
    records = [
        {"repo": f"org/e{i}", "languages": {"Elixir": 5000}}
        for i in range(cd.LANGUAGE_COVERAGE_THRESHOLD - 1)
    ]
    _write_lang_cache(ws, records)
    items = {i["item"]: i for i in cd.check_language_coverage(ws)}
    assert "language-coverage:Elixir" not in items
    assert items["language-coverage"]["status"] == "fresh"


def test_language_coverage_ecosystem_zero_edges_is_drift(tmp_path):
    """A deps-multi-stats.json ecosystem with manifests but 0 dep_edges is
    a coverage regression; a healthy ecosystem is informational; global
    scalar keys are not mistaken for ecosystems."""
    ws = _mk_ws(tmp_path)
    _write_lang_cache(ws, [{"repo": "org/a", "languages": {"Go": 100}}])
    stats = {
        "npm": {"repos_with_manifest": 12, "dep_edges": 450},
        "cargo": {"repos_with_manifest": 3, "dep_edges": 0},
        "repos_tree_ok": 100,
        "loud_fail": ["cargo"],
    }
    (ws / "analysis-results" / "graph" / "deps-multi-stats.json").write_text(json.dumps(stats))
    items = {i["item"]: i for i in cd.check_language_coverage(ws)}
    assert items["language-coverage:eco:cargo"]["status"] == "drift"
    assert "0 dep_edges" in items["language-coverage:eco:cargo"]["detail"]
    assert items["language-coverage:eco:npm"]["status"] == "fresh"
    assert "language-coverage:eco:repos_tree_ok" not in items
    assert "language-coverage:eco:loud_fail" not in items


def test_language_coverage_dominant_is_max_bytes(tmp_path):
    """Dominance is decided by max bytes, not language presence: an
    uncovered language present but never dominant does not flag."""
    ws = _mk_ws(tmp_path)
    # Kotlin present in many repos but Go always dominant -> no flag
    records = [
        {"repo": f"org/g{i}", "languages": {"Go": 9000, "Kotlin": 100}}
        for i in range(cd.LANGUAGE_COVERAGE_THRESHOLD + 5)
    ]
    _write_lang_cache(ws, records)
    items = {i["item"]: i for i in cd.check_language_coverage(ws)}
    assert "language-coverage:Kotlin" not in items
    # Go is dominant but covered by the go.mod L1 lane
    # (GRAPHED_NON_MANIFEST_LANGUAGES) — it must NOT flag, or the dominant
    # portfolio language would trip the tripwire on every run.
    assert "language-coverage:Go" not in items
    assert items["language-coverage"]["status"] == "fresh"


# --- language-cache freshness: the coverage-backstop staleness row ------


def test_language_cache_freshness_missing_is_drift(tmp_path):
    ws = _mk_ws(tmp_path)
    res = cd.check_language_cache_freshness(ws)[0]
    assert res["item"] == "language-cache-freshness"
    assert res["status"] == "drift"
    assert "missing" in res["detail"]
    assert "refresh" in res


def test_language_cache_freshness_fresh_then_stale(tmp_path):
    import os

    ws = _mk_ws(tmp_path)
    p = _write_lang_cache(ws, [{"repo": "org/a", "languages": {"Go": 100}}])
    # a just-written cache is fresh
    now = cd._now().timestamp()
    os.utime(p, (now, now))
    fresh = cd.check_language_cache_freshness(ws)[0]
    assert fresh["status"] == "fresh"
    assert "refresh" not in fresh
    # an old cache past the threshold flags drift with a refresh command
    old = (cd._now() - datetime.timedelta(days=cd.LANGUAGE_CACHE_MAX_AGE_DAYS + 5)).timestamp()
    os.utime(p, (old, old))
    stale = cd.check_language_cache_freshness(ws)[0]
    assert stale["status"] == "drift"
    assert "refresh" in stale
    assert "loc-dashboard" in stale["refresh"]


# --- threat-model staleness row (re-model lane dead-timer backstop) ---


def _tm(ws, product, repo, date_str, with_section7=True):
    d = ws / "analysis-results" / "findings" / product / repo
    d.mkdir(parents=True, exist_ok=True)
    body = f"# Threat Model: {product}/{repo}\n\n## 1. System context\n\nx\n"
    if with_section7:
        body += (
            f"\n## 7. Provenance\n\n- mode: bootstrap\n"
            f"- date: {date_str}\n"
            f"- target: https://github.com/{product}/{repo} @ abc1234\n"
            f"- harness_version: 0.237.0\n"
        )
    (d / f"{repo}-threat-model.md").write_text(body, encoding="utf-8")


def _today_minus(days):
    import datetime as _dt

    return (_dt.datetime.now(_dt.UTC).date() - _dt.timedelta(days=days)).isoformat()


def test_threat_model_flags_old_models(tmp_path):
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    _tm(ws, "prodA", "fresh-repo", _today_minus(10))
    _tm(ws, "prodB", "old-repo", _today_minus(400))
    rows = cd.check_threat_model_staleness(ws)
    assert len(rows) == 1 and rows[0]["item"] == "threat-model"
    assert rows[0]["status"] == "stale"
    assert "old-repo" in rows[0]["detail"]
    assert "fresh-repo" not in rows[0]["detail"]
    assert "refresh" in rows[0]  # actionable pointer present


def test_threat_model_all_fresh(tmp_path):
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    _tm(ws, "p", "r1", _today_minus(5))
    rows = cd.check_threat_model_staleness(ws)
    assert rows[0]["status"] == "fresh"
    assert "1 model" in rows[0]["detail"]


def test_threat_model_undated_counted(tmp_path):
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    _tm(ws, "p", "r-undated", "n/a", with_section7=False)
    rows = cd.check_threat_model_staleness(ws)
    assert rows[0]["item"] == "threat-model"
    assert "undated" in rows[0]["detail"]


def test_threat_model_pending_when_none(tmp_path):
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    rows = cd.check_threat_model_staleness(ws)
    assert rows[0]["status"] == "pending"


def test_threat_model_threshold_locked_to_router_cadence():
    """The drift row is the dead-timer for the router's quarterly
    threat-model lane. If the two thresholds drift apart the row either
    can never fire (drift > lane) or is permanently stale (drift <
    lane) — either way it stops meaning anything."""
    spec = importlib.util.spec_from_file_location(
        "_brw", Path(cd.__file__).with_name("build_rescan_worklist.py")
    )
    brw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(brw)
    assert cd.THREAT_MODEL_STALE_DAYS == brw.THREAT_MODEL_QUARTERLY_DAYS


def test_threat_model_refresh_points_at_the_lane(tmp_path):
    """A stale row must name the lane that stopped draining — the old
    'no re-model lane exists yet' text is now false."""
    ws = tmp_path / "ws"
    (ws / "analysis-results" / "findings").mkdir(parents=True)
    _tm(ws, "p", "stale-repo", _today_minus(200))
    rows = cd.check_threat_model_staleness(ws)
    assert rows[0]["status"] == "stale"
    assert "threat-model-quarterly" in rows[0]["refresh"]
    assert "no re-model lane" not in rows[0]["refresh"]


# --- argus-observe-rules pin (opt-in crypto/PQC supplement) ---


def test_argus_pin_parses_from_run_opengrep():
    """The row reads the pin out of run_opengrep.py by regex. If the
    constants are renamed the row degrades to `unavailable` rather than
    silently reporting fresh — assert it can still find them."""
    rows = cd.check_argus_rules_pin(Path(cd.__file__).resolve().parents[1])
    assert rows[0]["item"] == "argus-rules-pin"
    detail = rows[0]["detail"]
    # check_argus_rules_pin returns "unavailable" for two unrelated reasons:
    # the regex found nothing (what this test guards) and `git ls-remote`
    # could not reach upstream (no egress from the shared runner). Only the
    # first is a defect; skip on the second rather than reporting the
    # network as a renamed constant.
    if rows[0]["status"] == "unavailable" and detail.startswith("cannot reach"):
        pytest.skip(f"no egress to upstream: {detail}")
    assert rows[0]["status"] != "unavailable", detail


def test_argus_pin_is_registered_in_checks():
    """An unregistered check never runs — registration IS the wiring."""
    assert cd.check_argus_rules_pin in cd.CHECKS


def test_argus_pack_is_not_the_default_rules_source():
    """~500 rules uncalibrated against our triage-ledger ground truth
    must stay opt-in. If this fails, someone promoted the pack without
    the opengrep-ruleset-plan gate (>=3 rediscoveries, precision >~50%)."""
    import traust_engine.adapters.opengrep as _og

    src = Path(_og.__file__).read_text(encoding="utf-8")
    assert "ARGUS_RULES_REPO" in src
    # the default pack constant is the traust-authored one
    default = src.split("Default (no --rules):", 1)[1][:200]
    assert "traust-authored" in default, default


# --- pqc-backfeed: graph $.pqc coverage vs the pqc corpus ----------------


def _seed_graph_with_pqc(ws, n_with_pqc, n_plain=0):
    """A minimal portfolio-graph.db carrying `n_with_pqc` repo nodes with a
    `$.pqc` attr and `n_plain` repo nodes without — the shape the backfeed
    produces / a rebuild clobbers."""
    import sqlite3

    db = ws / "analysis-results" / "graph" / "portfolio-graph.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, kind TEXT, label TEXT, attrs TEXT)")
    for i in range(n_with_pqc):
        con.execute(
            "INSERT INTO nodes VALUES (?,?,?,?)",
            (f"repo:r{i}", "repo", f"r{i}", json.dumps({"pqc": {"overall": 1}})),
        )
    for i in range(n_plain):
        con.execute(
            "INSERT INTO nodes VALUES (?,?,?,?)", (f"repo:p{i}", "repo", f"p{i}", json.dumps({}))
        )
    con.commit()
    con.close()
    return db


def test_pqc_backfeed_absent_db_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    res = cd.check_pqc_backfeed(ws)[0]
    assert res["item"] == "pqc-backfeed"
    assert res["status"] == "pending"
    assert "portfolio-graph.db" in res["detail"]


def test_pqc_backfeed_drift_when_graph_below_corpus(tmp_path):
    ws = _mk_ws(tmp_path)
    # graph has only a few $.pqc repos ...
    _seed_graph_with_pqc(ws, n_with_pqc=3, n_plain=2)
    # ... but the facts corpus is much larger (20 repos)
    for i in range(20):
        _write_facts(ws, f"repo{i}", _facts_doc())
    res = cd.check_pqc_backfeed(ws)[0]
    assert res["status"] == "drift"
    assert "clobbered" in res["detail"]
    assert "3 of 20" in res["detail"]
    assert "scan_pqc_dependencies" in res["refresh"]


def test_pqc_backfeed_fresh_when_counts_match(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_graph_with_pqc(ws, n_with_pqc=10)
    for i in range(10):
        _write_facts(ws, f"repo{i}", _facts_doc())
    res = cd.check_pqc_backfeed(ws)[0]
    assert res["status"] == "fresh"
    assert "10 of 10" in res["detail"]
    assert "refresh" not in res


def test_pqc_backfeed_prefers_summary_repos_with_pqc_attrs(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_graph_with_pqc(ws, n_with_pqc=40)
    (ws / "analysis-results/graph/pqc-backfeed-summary.json").write_text(
        json.dumps({"repos_with_pqc_attrs": 3142})
    )
    res = cd.check_pqc_backfeed(ws)[0]
    assert res["status"] == "drift"
    assert "40 of 3142" in res["detail"]


def test_pqc_backfeed_no_corpus_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_graph_with_pqc(ws, n_with_pqc=5)
    # db present but neither a summary nor a facts corpus to compare against
    res = cd.check_pqc_backfeed(ws)[0]
    assert res["status"] == "pending"
    assert "compare" in res["detail"]


# ---------------------------------------------------------------------------
# reachability coverage + watch register (v0.261.0)
# ---------------------------------------------------------------------------


def _seed_lang_cache(ws, rows):
    """rows: list of dicts {language: bytes} — one repo per row."""
    p = ws / cd.LANG_CACHE_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps({"languages": r}) for r in rows) + "\n", encoding="utf-8")
    return p


def _seed_watch(ws, reviewed, cadence=92, n=2):
    p = _home() / cd.REACHABILITY_WATCH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f'reviewed: "{reviewed}"\nreview_cadence_days: {cadence}\n'
        "watch:\n" + "".join(f"  - id: w{i}\n    question: q\n" for i in range(n)),
        encoding="utf-8",
    )
    return p


def test_reachability_coverage_flags_uncovered_high_mass_language(tmp_path):
    ws = _mk_ws(tmp_path)
    n = cd.REACHABILITY_COVERAGE_THRESHOLD
    _seed_lang_cache(ws, [{"Python": 100}] * n + [{"Go": 100}] * n)
    _seed_watch(ws, cd._now().date().isoformat())
    items = {i["item"]: i for i in cd.check_reachability_coverage(ws)}
    assert items["reachability-coverage:Python"]["status"] == "drift"
    # Go has an engine wired -> never flagged
    assert "reachability-coverage:Go" not in items
    assert f"dominant in {n} repos" in items["reachability-coverage:Python"]["detail"]
    # the row must point at the watch register for the accept-decision path
    assert cd.REACHABILITY_WATCH in items["reachability-coverage:Python"]["refresh"]


def test_reachability_coverage_respects_threshold(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_lang_cache(ws, [{"Python": 100}] * (cd.REACHABILITY_COVERAGE_THRESHOLD - 1))
    _seed_watch(ws, cd._now().date().isoformat())
    items = {i["item"]: i for i in cd.check_reachability_coverage(ws)}
    assert "reachability-coverage:Python" not in items
    assert items["reachability-coverage"]["status"] == "fresh"


def test_reachability_coverage_ignores_no_deps_languages(tmp_path):
    ws = _mk_ws(tmp_path)
    n = cd.REACHABILITY_COVERAGE_THRESHOLD
    _seed_lang_cache(ws, [{"Shell": 100}] * n + [{"YAML": 100}] * n)
    _seed_watch(ws, cd._now().date().isoformat())
    items = {i["item"]: i for i in cd.check_reachability_coverage(ws)}
    assert "reachability-coverage:Shell" not in items
    assert "reachability-coverage:YAML" not in items
    assert items["reachability-coverage"]["status"] == "fresh"


def test_reachability_coverage_every_engine_language_is_covered(tmp_path):
    """Wiring an engine must silence the row — the map IS the claim."""
    ws = _mk_ws(tmp_path)
    n = cd.REACHABILITY_COVERAGE_THRESHOLD
    rows = []
    for lang in cd.REACHABILITY_ENGINES:
        rows += [{lang: 100}] * n
    _seed_lang_cache(ws, rows)
    _seed_watch(ws, cd._now().date().isoformat())
    items = {i["item"]: i for i in cd.check_reachability_coverage(ws)}
    assert items["reachability-coverage"]["status"] == "fresh"


def test_reachability_coverage_no_cache_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_watch(ws, cd._now().date().isoformat())
    items = {i["item"]: i for i in cd.check_reachability_coverage(ws)}
    assert items["reachability-coverage"]["status"] == "pending"


def test_reachability_watch_review_clock(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_lang_cache(ws, [{"Go": 100}])
    _seed_watch(ws, cd._now().date().isoformat())
    row = {i["item"]: i for i in cd.check_reachability_coverage(ws)}["reachability-watch:review"]
    assert row["status"] == "fresh"
    assert "2 watch condition(s)" in row["detail"]

    old = (cd._now() - datetime.timedelta(days=200)).date().isoformat()
    _seed_watch(ws, old)
    row = {i["item"]: i for i in cd.check_reachability_coverage(ws)}["reachability-watch:review"]
    assert row["status"] == "stale"
    assert cd.REACHABILITY_WATCH in row["refresh"]


def test_reachability_watch_missing_register_is_pending(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_lang_cache(ws, [{"Go": 100}])
    row = {i["item"]: i for i in cd.check_reachability_coverage(ws)}["reachability-watch:review"]
    assert row["status"] == "pending"


def test_reachability_watch_unquoted_yaml_date_parses(tmp_path):
    """PyYAML loads a bare YYYY-MM-DD as datetime.date, not str."""
    ws = _mk_ws(tmp_path)
    _seed_lang_cache(ws, [{"Go": 100}])
    p = _home() / cd.REACHABILITY_WATCH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"reviewed: {cd._now().date().isoformat()}\nwatch: []\n", encoding="utf-8")
    row = {i["item"]: i for i in cd.check_reachability_coverage(ws)}["reachability-watch:review"]
    assert row["status"] == "fresh"


def test_reachability_watch_bad_date_is_unavailable(tmp_path):
    ws = _mk_ws(tmp_path)
    _seed_lang_cache(ws, [{"Go": 100}])
    p = _home() / cd.REACHABILITY_WATCH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('reviewed: "not-a-date"\nwatch: []\n', encoding="utf-8")
    row = {i["item"]: i for i in cd.check_reachability_coverage(ws)}["reachability-watch:review"]
    assert row["status"] == "unavailable"


def test_reachability_check_is_registered():
    assert cd.check_reachability_coverage in cd.CHECKS


# --- untagged/HEAD build handling in the external-tools version probe ---


def test_untagged_build_reports_unavailable_not_stale(tmp_path, monkeypatch):
    """A HEAD/SNAPSHOT self-report must not be compared as a version."""
    _patch_tools(monkeypatch, local=cd._UNTAGGED, upstream=("4.0.601", None), expected="4.0.600")
    items = cd.check_external_tools(_mk_ws(tmp_path))
    assert items[0]["status"] == "unavailable"
    assert "untagged" in items[0]["detail"]
    assert "tagged release" in items[0]["refresh"]


def test_version_probe_returns_untagged_on_head_banner(monkeypatch):
    class _P:
        stdout = "Version: HEAD+20260810-0912\n"
        stderr = ""

    monkeypatch.setattr(cd.subprocess, "run", lambda *a, **k: _P())
    assert cd._installed_tool_version(["joern", "--version"]) == cd._UNTAGGED


def test_version_probe_prefers_a_real_semver_over_the_marker(monkeypatch):
    class _P:
        stdout = "SNAPSHOT build\nVersion: 4.0.601\n"
        stderr = ""

    monkeypatch.setattr(cd.subprocess, "run", lambda *a, **k: _P())
    assert (
        cd._installed_tool_version(["joern", "--version"], r"Version:\s*(\d+)\.(\d+)\.(\d+)")
        == "4.0.601"
    )


def test_version_probe_unparseable_stays_none(monkeypatch):
    class _P:
        stdout = "no version here"
        stderr = ""

    monkeypatch.setattr(cd.subprocess, "run", lambda *a, **k: _P())
    assert cd._installed_tool_version(["fakescan", "--version"]) is None


def test_version_probe_devnulls_stdin(monkeypatch):
    """Regression: a REPL-fallthrough probe must not read the run's stdin."""
    seen = {}

    class _P:
        stdout = "1.2.3"
        stderr = ""

    def _run(*a, **k):
        seen.update(k)
        return _P()

    monkeypatch.setattr(cd.subprocess, "run", _run)
    cd._installed_tool_version(["fakescan", "--version"])
    assert seen.get("stdin") == cd.subprocess.DEVNULL


def test_joern_row_is_in_the_shipped_manifest_and_allowlisted():
    tools, err = cd._load_external_tools()
    assert err is None, err
    joern = [t for t in tools if t["name"] == "joern"]
    assert joern, "joern must carry an external-tools freshness row"
    spec = joern[0]
    assert spec["argv"][0] in cd._VERSION_CMD_BINARIES
    # must NOT use the bare-first-semver heuristic: joern's output quotes
    # the install path and the bundled Scala jar version
    assert spec["version_re"] != cd._SEMVER_RE
    assert "Version" in spec["version_re"]


# ---------------------------------------------------------------------------
# dependency pins vs installed versions (v0.277.0)
#
# Replaced the submodule check when the C8 restructure swapped the
# contracts/traust-ledger git submodules for pip deps. Same failure class, new
# mechanism: "a dependency is not the version this tree expects", surfacing as
# an import error that names neither the dependency system nor the fix.
#   submodules (2026-08-13): 18 test modules died at collection after v0.267.0
#                            bumped traust-ledger -> "cannot import name
#                            'stamp_and_sign'"
#   pip deps   (2026-08-14): traust_engine simply absent until `uv sync` ->
#                            "No module named 'traust_engine'"
# CI cannot cover it: CI builds its own venv, while skills run on the operator
# workstation.
# ---------------------------------------------------------------------------

_PJ_PINS = (
    "[tool.uv.sources]\n"
    'traust-engine = { git = "ssh://git@example.com/he.git", tag = "v0.1.5" }\n'
    'traust-ledger = { git = "ssh://git@example.com/lc.git", tag = "v0.1.2" }\n'
)


def _pin_env(monkeypatch, pyproject, installed):
    """Pin declarations in pyproject + what importlib.metadata reports."""
    import importlib.metadata as md

    monkeypatch.setattr(cd.Path, "is_file", lambda self: True)
    monkeypatch.setattr(cd.Path, "read_text", lambda self, **kw: pyproject)

    def _version(name):
        if name not in installed:
            raise md.PackageNotFoundError(name)
        return installed[name]

    monkeypatch.setattr(md, "version", _version)


def test_pins_matching_installed_is_fresh(tmp_path, monkeypatch):
    _pin_env(monkeypatch, _PJ_PINS, {"traust-engine": "0.1.5", "traust-ledger": "0.1.2"})
    items = cd.check_dependency_pins(_mk_ws(tmp_path))
    assert {i["status"] for i in items} == {"fresh"}
    assert {i["item"] for i in items} == {
        "dependency-pins:traust-engine",
        "dependency-pins:traust-ledger",
    }


def test_absent_dependency_is_drift(tmp_path, monkeypatch):
    """The 2026-08-14 failure: traust_engine missing until `uv sync`."""
    _pin_env(monkeypatch, _PJ_PINS, {"traust-ledger": "0.1.2"})
    items = [i for i in cd.check_dependency_pins(_mk_ws(tmp_path)) if i["status"] != "fresh"]
    assert len(items) == 1
    assert "NOT INSTALLED" in items[0]["detail"]
    assert items[0]["refresh"] == "uv sync"


def test_version_skew_is_drift(tmp_path, monkeypatch):
    _pin_env(monkeypatch, _PJ_PINS, {"traust-engine": "0.0.9", "traust-ledger": "0.1.2"})
    items = [i for i in cd.check_dependency_pins(_mk_ws(tmp_path)) if i["status"] != "fresh"]
    assert len(items) == 1
    assert "VERSION SKEW" in items[0]["detail"]
    assert "v0.1.5" in items[0]["detail"]


def test_no_git_tag_pins_is_fresh(tmp_path, monkeypatch):
    _pin_env(monkeypatch, "[project]\nname = 'x'\n", {})
    items = cd.check_dependency_pins(_mk_ws(tmp_path))
    assert items[0]["status"] == "fresh"
    assert "no git-tag-pinned" in items[0]["detail"]


def test_unreadable_pyproject_is_unavailable_not_fresh(tmp_path, monkeypatch):
    """A checker that cannot read its input must never report a false pass."""
    monkeypatch.setattr(cd.Path, "is_file", lambda self: False)
    items = cd.check_dependency_pins(_mk_ws(tmp_path))
    assert items[0]["status"] == "unavailable"


def test_dependency_pin_check_is_registered():
    assert cd.check_dependency_pins in cd.CHECKS


# --------------------------------------------------------------------------
# identity corpus sweep — the boundary check analysis-results has no hook for
# --------------------------------------------------------------------------


def test_render_md_survives_the_info_status():
    """Two checks emit `info`; the renderer's order tuple omitted it and raised."""
    md = cd.render_md(
        {
            "metadata": {"generated_at": "t", "harness_version": "v"},
            "items": [{"item": "x", "status": "info", "detail": "d"}],
        }
    )
    assert "| x | info |" in md


def test_render_md_tolerates_an_unknown_status():
    md = cd.render_md(
        {
            "metadata": {"generated_at": "t", "harness_version": "v"},
            "items": [{"item": "x", "status": "brand-new", "detail": "d"}],
        }
    )
    assert "brand-new" in md


def _grype_status(monkeypatch, out, on_path=True):
    """Stub `grype db status` output (and PATH presence) for check_grype_db."""
    monkeypatch.setattr(
        cd.shutil if hasattr(cd, "shutil") else __import__("shutil"),
        "which",
        lambda _n: "/usr/bin/grype" if on_path else None,
    )
    monkeypatch.setattr(
        cd.subprocess,
        "run",
        lambda *a, **k: type("R", (), {"stdout": out, "stderr": "", "returncode": 0})(),
    )


def test_grype_db_pending_when_not_installed(tmp_path, monkeypatch):
    _grype_status(monkeypatch, "", on_path=False)
    res = cd.check_grype_db(tmp_path)[0]
    assert res["item"] == "grype-db"
    assert res["status"] == "pending"


def test_grype_db_fresh_when_current(tmp_path, monkeypatch):
    now = datetime.datetime.now(datetime.UTC)
    _grype_status(monkeypatch, f"Built:     {now:%Y-%m-%dT%H:%M:%SZ}\nStatus:    valid\n")
    res = cd.check_grype_db(tmp_path)[0]
    assert res["status"] == "fresh"
    assert "0d ago" in res["detail"]


def test_grype_db_stale_on_age_even_when_grype_says_valid(tmp_path, monkeypatch):
    """The DB ages past usefulness before grype self-invalidates it; the row
    must fire on age, not wait for grype to agree."""
    old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=9)
    _grype_status(monkeypatch, f"Built:     {old:%Y-%m-%dT%H:%M:%SZ}\nStatus:    valid\n")
    res = cd.check_grype_db(tmp_path)[0]
    assert res["status"] == "stale"
    assert "grype db update" in res["refresh"]


def test_grype_db_stale_when_status_invalid(tmp_path, monkeypatch):
    recent = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    _grype_status(monkeypatch, f"Built:     {recent:%Y-%m-%dT%H:%M:%SZ}\nStatus:    invalid\n")
    assert cd.check_grype_db(tmp_path)[0]["status"] == "stale"


def test_grype_db_unparseable_is_unavailable_not_fresh(tmp_path, monkeypatch):
    """A changed output shape must never read as fresh — that would hide
    exactly the staleness this row exists to catch."""
    for out in ("something else entirely\n", "Built:     not-a-date\n"):
        _grype_status(monkeypatch, out)
        assert cd.check_grype_db(tmp_path)[0]["status"] == "unavailable"


# --- feed-source liveness rows ------------------------------------------
# The live tier had no freshness signal at all: fetch_advisory's `csaf`
# source requested advisories/<cve>.json and 404'd for every CVE ever
# passed to it, indefinitely, because a hardcoded URL has no registry to
# inspect and no check to fail (measured 2026-08-25).


def _probe_registry(tmp_path, **over):
    import yaml

    spec = {
        "tier": "live",
        "url_template": "https://h.example/{ident}",
        "license": {"id": "x", "terms": "t", "url": "u"},
        "consumers": ["t"],
        "probe": {"ident": "A", "expect_status": 200},
    }
    spec.update(over)
    p = tmp_path / "feeds.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "sources": {"s": spec}}))
    return p


def _patch_registry(monkeypatch, path):
    from traust.registry import feeds_config as fc

    monkeypatch.setattr(fc, "registry_path", lambda: path)


def _fake_urlopen(monkeypatch, exc=None, status=200):
    import urllib.request

    class _R:
        def __init__(self):
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _open(*a, **k):
        if exc:
            raise exc
        return _R()

    monkeypatch.setattr(urllib.request, "urlopen", _open)


def test_feed_source_http_error_is_drift_not_stale(tmp_path, monkeypatch):
    """A 404 is a determined disagreement between registry and service."""
    import urllib.error

    _patch_registry(monkeypatch, _probe_registry(tmp_path))
    _fake_urlopen(monkeypatch, exc=urllib.error.HTTPError("u", 404, "Not Found", {}, None))
    r = cd.check_feed_sources(tmp_path)[0]
    assert r["item"] == "feed-source:s"
    assert r["status"] == "drift"
    assert "404" in r["detail"]
    assert "config/feeds.yaml" in r["refresh"]


def test_feed_source_network_failure_is_unavailable_not_drift(tmp_path, monkeypatch):
    """An offline workstation must not report every source as broken."""
    import urllib.error

    _patch_registry(monkeypatch, _probe_registry(tmp_path))
    _fake_urlopen(monkeypatch, exc=urllib.error.URLError("offline"))
    r = cd.check_feed_sources(tmp_path)[0]
    assert r["status"] == "unavailable"
    assert "undetermined" in r["detail"]


def test_feed_source_ok_is_fresh(tmp_path, monkeypatch):
    _patch_registry(monkeypatch, _probe_registry(tmp_path))
    _fake_urlopen(monkeypatch, status=200)
    assert cd.check_feed_sources(tmp_path)[0]["status"] == "fresh"


def test_feed_source_unexpected_status_is_drift(tmp_path, monkeypatch):
    _patch_registry(monkeypatch, _probe_registry(tmp_path))
    _fake_urlopen(monkeypatch, status=204)
    r = cd.check_feed_sources(tmp_path)[0]
    assert r["status"] == "drift" and "expected 200" in r["detail"]


def test_unloadable_registry_is_one_loud_row(tmp_path, monkeypatch):
    _patch_registry(monkeypatch, tmp_path / "absent.yaml")
    rows = cd.check_feed_sources(tmp_path)
    assert len(rows) == 1 and rows[0]["status"] == "unavailable"


def test_every_cached_source_in_the_registry_gets_a_row():
    """A hardcoded feed list is how a newly added feed goes unmonitored: the rows come from the
    feeds core registers from the same registry."""
    from traust_core.v1.context import Config, Context

    from traust.registry import feeds_config as fc

    core = Context(Config())
    core.register_feeds(fc.registry_path())
    assert set(core.feeds.names()) == set(fc.cached_sources())


# --- floor-only tool rows ---------------------------------------------------
# A tool may be floor-tracked without an upstream to compare against. Go tags
# releases goX.Y.Z rather than vX.Y.Z, so a semver staleness check would answer
# confidently and wrongly. Requiring upstream on every row made the manifest
# unable to say that -- and worse, ONE such row turned the whole roster
# 'unavailable', silently dropping freshness for all eleven other tools.


def test_roster_loads_with_the_go_row():
    tools, err = cd._load_external_tools()
    assert err is None
    assert "go" in {t["name"] for t in tools}


def test_go_row_is_floor_only():
    tools, _ = cd._load_external_tools()
    go = next(t for t in tools if t["name"] == "go")
    assert go["kind"] is None and go["ref"] is None
    assert go["expected"] == "1.24.0"


def test_half_specified_upstream_is_still_refused(tmp_path, monkeypatch):
    """One of kind/ref is a typo, not a decision."""
    import yaml as _yaml

    p = tmp_path / "external-tools.yaml"
    p.write_text(
        _yaml.safe_dump(
            {
                "tools": [
                    {
                        "name": "grype",
                        "version_cmd": ["grype", "--version"],
                        "upstream": {"kind": "github"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cd, "EXTERNAL_TOOLS_MANIFEST", p)
    tools, err = cd._load_external_tools()
    assert tools is None
    assert "kind and ref, or neither" in err


def test_mewt_is_allowlisted_but_only_for_version():
    """mewt runs target test suites, so only its version probe is grantable.

    Adding a roster row without the allowlist entry fails the whole load
    closed (every external-tools row goes `unavailable`), which is how the
    2026-09-15 mewt intake was caught.
    """
    assert cd._vet_version_cmd(["mewt", "--version"]) is None
    for argv in (["mewt", "run", "."], ["mewt", "mutate", "x.go"], ["mewt", "print"]):
        assert cd._vet_version_cmd(argv) is not None, argv


def test_go_is_allowlisted_but_only_for_version():
    assert cd._vet_version_cmd(["go", "version"]) is None
    for argv in (["go", "run", "x"], ["go", "generate"], ["go", "build"]):
        assert cd._vet_version_cmd(argv) is not None, argv


# --- check_sibling_readmes: module surface resolved from the checkout ---------
#
# Regression for 2026-09-07: the check compared README-named modules against a
# hardcoded ["identity", "events", "writer", "integrity"] list, so after the
# ledger's restructure into api/, client, config, handlers every CORRECT README
# mention was reported as "not a module" while the four accepted names no longer
# existed. The surface must come from the tree.

_PYPROJECT = (
    '[project]\ndependencies = ["traust-contracts>=1.2.0,<2"]\n'
    '[tool.uv.sources]\ntraust-contracts = { git = "x", tag = "v1.2.0" }\n'
)
_PINS_OK = '"traust-contracts>=1.2.0,<2"\ntraust-contracts = { git = "x", tag = "v1.2.0" }\n'


def _fake_ledger(tmp_path, monkeypatch):
    ws = tmp_path
    root = ws / "fake-ledger"
    pk = root / "src" / "fake_ledger"
    (pk / "api").mkdir(parents=True)
    (pk / "_internal").mkdir()
    (pk / "__init__.py").write_text("")
    (pk / "client.py").write_text('__all__ = ["LedgerClient"]\nclass LedgerClient: pass\n')
    (pk / "api" / "__init__.py").write_text("")
    (pk / "api" / "identity.py").write_text(
        '__all__ = ["fingerprint", "canon_repo"]\ndef fingerprint(): pass\ndef canon_repo(): pass\n'
    )
    (pk / "_internal" / "__init__.py").write_text("")
    (pk / "_internal" / "identity.py").write_text("")
    (pk / "needs_extra.py").write_text("import no_such_third_party_dep_xyz\n")
    (pk / "dangling.py").write_text("from fake_ledger.gone import x\n")
    (root / "pyproject.toml").write_text(_PYPROJECT)
    monkeypatch.syspath_prepend(str(root / "src"))
    for m in [k for k in sys.modules if k == "fake_ledger" or k.startswith("fake_ledger.")]:
        del sys.modules[m]
    sib = {"fake-ledger": ("fake_ledger", ("fake-ledger",))}
    return ws, root, pk, sib


def test_module_path_exists_walks_the_tree(tmp_path, monkeypatch):
    _, _, pk, _ = _fake_ledger(tmp_path, monkeypatch)
    assert cd._module_path_exists(pk, ["client"])
    assert cd._module_path_exists(pk, ["api"])
    assert cd._module_path_exists(pk, ["api", "identity"])
    assert not cd._module_path_exists(pk, ["nope"])
    assert not cd._module_path_exists(pk, ["api", "missing"])
    # private surface never resolves, even though it imports
    assert not cd._module_path_exists(pk, ["_internal", "identity"])
    assert not cd._module_path_exists(pk, [])


def test_sibling_readme_accepts_modules_that_exist_in_tree(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    (root / "README.md").write_text(
        _PINS_OK + "`fake_ledger.client` exports `LedgerClient`. `fake_ledger.api.identity` "
        "exports `fingerprint` and `canon_repo`. `fake_ledger.needs_extra` is server-only.\n"
    )
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert out["status"] == "fresh", out["detail"]


def test_sibling_readme_flags_missing_and_private_modules(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    (root / "README.md").write_text(
        _PINS_OK
        + "See `fake_ledger.client`, `fake_ledger.nope`, `fake_ledger._internal.identity`.\n"
    )
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert out["status"] == "drift"
    assert "README names fake_ledger.nope, which is not a module" in out["detail"]
    assert "README names fake_ledger._internal.identity, which is not a module" in out["detail"]
    assert "fake_ledger.client, which is not a module" not in out["detail"]


def test_sibling_readme_flags_missing_submodule_of_real_package(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    (root / "README.md").write_text(_PINS_OK + "See `fake_ledger.api.missing`.\n")
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert "README names fake_ledger.api.missing, which is not a module" in out["detail"]


def test_sibling_readme_pin_mismatch_still_reported(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    (root / "README.md").write_text(
        '"traust-contracts>=1.0.0,<2"\ntraust-contracts = { git = "x", tag = "v1.0.0" }\n'
        "`fake_ledger.client` exports `LedgerClient`.\n"
    )
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert (
        "README pins traust-contracts>=1.0.0,<2 but pyproject pins traust-contracts>=1.2.0,<2"
        in out["detail"]
    )
    assert "README pins traust-contracts tag v1.0.0 but pyproject pins v1.2.0" in out["detail"]


def test_sibling_readme_undocumented_exports_scoped_to_documented_modules(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    # client is NOT mentioned, so its LedgerClient export must not be demanded
    (root / "README.md").write_text(
        _PINS_OK + "`fake_ledger.api.identity` exports `fingerprint`.\n"
    )
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert (
        "1 exported name(s) absent from the README: fake_ledger.api.identity.canon_repo"
        in out["detail"]
    )
    assert "LedgerClient" not in out["detail"]


def test_sibling_readme_missing_third_party_dep_is_not_drift(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    (root / "README.md").write_text(
        _PINS_OK + "`fake_ledger.needs_extra` and `fake_ledger.dangling`.\n"
    )
    (out,) = cd.check_sibling_readmes(ws, sib)
    # a venv without the sibling's server extras is not a README defect...
    assert "needs_extra" not in out["detail"]
    # ...but a module that references a nonexistent module INSIDE the package is
    assert "fake_ledger.dangling (references fake_ledger.gone)" in out["detail"]


def test_sibling_readme_unavailable_without_src_tree(tmp_path, monkeypatch):
    ws, root, _, sib = _fake_ledger(tmp_path, monkeypatch)
    (root / "README.md").write_text(_PINS_OK)
    shutil.rmtree(root / "src")
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert out["status"] == "unavailable"
    assert "src/fake_ledger/" in out["detail"]


def test_sibling_readme_audits_the_checkout_not_the_installed_pin(tmp_path, monkeypatch):
    """Regression 2026-09-07: the export audit imported whatever version of the
    sibling this venv had installed (0.20.0) while the README beside the
    checkout described 0.20.2, so a fixed README kept reporting as drift. The
    audit must see the checkout's src/, even when an older copy of the same
    package is importable in-process."""
    ws, root, _pk, sib = _fake_ledger(tmp_path, monkeypatch)
    # An "installed" older copy: same package name, different surface, first on
    # THIS process's path — the trap the subprocess probe has to sidestep.
    stale = tmp_path / "site-packages" / "fake_ledger"
    stale.mkdir(parents=True)
    (stale / "__init__.py").write_text("")
    (stale / "client.py").write_text("class OldName: pass\n")
    monkeypatch.syspath_prepend(str(stale.parent))
    import importlib

    old = importlib.import_module("fake_ledger.client")
    assert hasattr(old, "OldName")  # the in-process view IS the stale copy
    (root / "README.md").write_text(_PINS_OK + "`fake_ledger.client` exports `LedgerClient`.\n")
    (out,) = cd.check_sibling_readmes(ws, sib)
    assert out["status"] == "fresh", out["detail"]
    assert "OldName" not in out["detail"]


def test_shipped_compliance_data_is_what_drift_watch_reads():
    """Provenance and catalogs come from traust-engine, not progress-tracker."""
    assert (cd._compliance_data() / "provenance.json").is_file()
    items = {i["item"]: i for i in cd.check_policy_provenance(Path("/nonexistent-ws"))}
    for name in ("compliance-spine", "catalog-pci-dss", "catalog-soc2-tsc", "catalog-gdpr"):
        assert items[f"provenance:{name}"]["status"] != "pending", items[f"provenance:{name}"]
