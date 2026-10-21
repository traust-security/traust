"""`traust adapters osv`: the OSV API is the default; degraded is exit 3, failed is exit 2."""

import json
from pathlib import Path
from types import SimpleNamespace

from traust.cli.groups import adapters


def _args(repo: Path, out: Path, source="api", sbom=None, grype=None):
    return SimpleNamespace(
        repo=repo,
        sbom=sbom,
        grype=grype,
        out=out,
        timeout=5,
        source=source,
        osv_scanner="osv-scanner",
        no_freeze=False,
    )


def _body(status, **extra):
    return {
        "provenance": {"source": "osv-api", "status": status, **extra},
        "candidates": [{"osv_id": "GHSA-x", "aliases": ["CVE-2026-1"]}],
    }


def test_complete_scan_writes_candidates(tmp_path, monkeypatch):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(osv_mod, "scan_api", lambda repo, client, resolver=None: _body("complete"))
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out)) == 0
    doc = json.loads(out.read_text())
    assert doc["metadata"]["artifact"] == "osv-dependency-candidates"
    assert doc["metadata"]["source"] == "osv-api"
    assert doc["candidates"][0]["osv_id"] == "GHSA-x"


def test_degraded_scan_exits_3_and_warns(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "scan_api",
        lambda repo, client, resolver=None: _body(
            "degraded", packages_unanswered=4, lookup_issues={"unreachable": 4}
        ),
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out)) == 3
    assert json.loads(out.read_text())["metadata"]["status"] == "degraded"
    assert "NOT clean" in capsys.readouterr().err


def test_not_a_directory(tmp_path):
    assert adapters.call_osv(None, _args(tmp_path / "missing", tmp_path / "o.json")) == 2


def test_partial_transitive_coverage_is_noted(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "scan_api",
        lambda repo, client, resolver=None: _body(
            "complete",
            transitive_coverage="partial",
            unresolved_manifests=[{"path": "pom.xml", "ecosystem": "Maven", "declarations": 3}],
        ),
    )
    assert adapters.call_osv(None, _args(tmp_path, tmp_path / "o.json")) == 0
    assert "without a lockfile are still unresolved" in capsys.readouterr().err


def test_an_unusable_api_is_an_error_exit_2(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    monkeypatch.setattr(
        osv_mod,
        "scan_api",
        lambda repo, client, resolver=None: {
            "provenance": {
                "source": "osv-api",
                "base_url": "https://osv.test/v1",
                "status": "failed",
                "failure": {"status": "unreachable", "detail": "URLError reaching it"},
            },
            "candidates": [],
        },
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out)) == 2
    assert json.loads(out.read_text())["metadata"]["status"] == "failed"
    err = capsys.readouterr().err
    assert "ERROR: OSV lookup failed at https://osv.test/v1 (unreachable)" in err
    assert "NOT a clean scan" in err


def _access(monkeypatch, mode):
    from traust.registry import osv_urls

    monkeypatch.setattr(osv_urls, "osv_access", lambda: mode)


def test_the_api_is_the_default_access(tmp_path, monkeypatch):
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "api")
    monkeypatch.setattr(osv_mod, "scan_api", lambda repo, client, resolver=None: _body("complete"))
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 0
    assert json.loads(out.read_text())["metadata"]["source"] == "osv-api"


def test_air_gapped_access_runs_osv_scanner_offline(tmp_path, monkeypatch):
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "air-gapped")
    seen = {}

    def fake_run(binary, repo, timeout, *, freeze):
        seen["freeze"] = freeze
        return SimpleNamespace(stdout='{"results": []}', stderr="", returncode=0), "osv-scanner"

    monkeypatch.setattr(osv_mod, "run_scanner", fake_run)
    monkeypatch.setattr(
        osv_mod, "scan_api", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no API"))
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 0
    assert seen["freeze"] is True  # --offline: never phones home
    assert json.loads(out.read_text())["metadata"]["source"] == "osv-scanner"


def test_air_gapped_without_osv_scanner_is_an_error_exit_2(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "air-gapped")

    def missing(*a, **k):
        raise FileNotFoundError("osv-scanner")

    monkeypatch.setattr(osv_mod, "run_scanner", missing)
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 2
    assert json.loads(out.read_text())["metadata"]["status"] == "failed"
    assert "the harness installs neither" in capsys.readouterr().err


def test_access_must_be_a_known_mode(tmp_path):
    import pytest

    from traust.registry import feeds_config

    path = tmp_path / "feeds.yaml"
    path.write_text(
        "version: 1\nsources:\n  osv:\n    tier: live\n    url_template: https://x/v1/query\n"
        "    access: offline\n    license: {id: x}\n",
        encoding="utf-8",
    )
    with pytest.raises(feeds_config.FeedsConfigError, match="access must be one of"):
        feeds_config.load(path)


def test_air_gapped_with_no_offline_database_is_an_error_not_clean(tmp_path, monkeypatch, capsys):
    """osv-scanner exits 127 with an empty JSON result when its database is missing."""
    from traust_engine.adapters import osv as osv_mod

    _access(monkeypatch, "air-gapped")
    err = (
        "Scanned go.mod file and found 77 packages\n"
        "could not load db for Go ecosystem: unable to fetch OSV database: "
        "no offline version of the OSV database is available\n"
    )
    monkeypatch.setattr(
        osv_mod,
        "run_scanner",
        lambda *a, **k: (
            SimpleNamespace(stdout='{"results": []}', stderr=err, returncode=127),
            "osv-scanner",
        ),
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(tmp_path, out, source=None)) == 2
    meta = json.loads(out.read_text())["metadata"]
    assert meta["status"] == "failed"
    assert "no offline version of the OSV database" in meta["failure"]["detail"]
    assert "NOT a clean scan" in capsys.readouterr().err


SYFT = {
    "source": {"name": "example/app"},
    "artifacts": [
        {
            "id": "r1",
            "type": "rpm",
            "purl": "pkg:rpm/redhat/python3-urllib3@1.26.5",
            "locations": [],
        },
        {
            "id": "p1",
            "type": "python",
            "purl": "pkg:pypi/urllib3@1.26.5",
            "locations": [{"path": "/usr/lib/python3.9/site-packages/urllib3"}],
        },
        {
            "id": "p2",
            "type": "python",
            "purl": "pkg:pypi/requests@2.19.0",
            "locations": [{"path": "/opt/app-root/lib/requests"}],
        },
    ],
    "artifactRelationships": [{"parent": "r1", "child": "p1", "type": "ownership-by-file-overlap"}],
}


def _sbom(tmp_path, doc=SYFT):
    p = tmp_path / "img.syft.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_sbom_scan_marks_grype_duplicates(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv_sbom

    def fake_scan(doc, client):
        packages, stats = osv_sbom.collect_sbom_packages(doc)
        assert set(packages) == {("PyPI", "requests", "2.19.0")}  # urllib3 is RPM-installed
        body = {
            "provenance": {"source": "osv-api", "status": "complete"},
            "candidates": [
                {
                    "osv_id": "GHSA-a",
                    "aliases": ["CVE-1"],
                    "ecosystem": "PyPI",
                    "package": "requests",
                    "found_version": "2.19.0",
                },
                {
                    "osv_id": "GHSA-b",
                    "aliases": [],
                    "ecosystem": "PyPI",
                    "package": "requests",
                    "found_version": "2.19.0",
                },
            ],
        }
        osv_sbom._with_stats(body["provenance"], stats, doc)
        return body

    _access(monkeypatch, "api")
    monkeypatch.setattr(osv_sbom, "scan_sbom", fake_scan)
    grype = tmp_path / "g.json"
    grype.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "artifact": {"purl": "pkg:pypi/requests@2.19.0"},
                        "vulnerability": {"id": "CVE-1"},
                    },
                    {
                        "artifact": {"type": "python", "purl": "pkg:pypi/urllib3@1.26.5"},
                        "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
                    },
                ]
            }
        )
    )
    out = tmp_path / "o.json"
    assert (
        adapters.call_osv(None, _args(None, out, source=None, sbom=_sbom(tmp_path), grype=grype))
        == 0
    )
    doc = json.loads(out.read_text())
    assert doc["metadata"]["sbom"].endswith("img.syft.json")
    assert doc["metadata"]["skipped_os_installed"] == 1
    assert doc["metadata"]["grype_dedupe"] == {"also_in_grype": 1, "osv_only": 1}
    assert [c["also_in_grype"] for c in doc["candidates"]] == [True, False]
    assert doc["metadata"]["grype_os_installed_matches"] == 1
    assert doc["grype_os_installed"][0]["package"] == "urllib3"
    err = capsys.readouterr().err
    assert "1 candidate(s) not reported by grype" in err
    assert "OS package installed" in err


def test_a_cyclonedx_sbom_is_refused_exit_2(tmp_path, capsys):
    cdx = tmp_path / "img.cdx.json"
    cdx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    assert adapters.call_osv(None, _args(None, tmp_path / "o.json", sbom=cdx)) == 2
    assert "syft JSON" in capsys.readouterr().err


def test_air_gapped_sbom_scan_runs_osv_scanner_on_the_filtered_packages(tmp_path, monkeypatch):
    from traust_engine.adapters import osv_sbom

    _access(monkeypatch, "air-gapped")
    seen = {}

    def fake_offline(binary, cdx, timeout):
        seen["purls"] = [c["purl"] for c in json.loads(Path(cdx).read_text())["components"]]
        return SimpleNamespace(
            stdout='{"results": []}', stderr="", returncode=0
        ), "osv-scanner -L x"

    monkeypatch.setattr(osv_sbom, "run_offline", fake_offline)
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(None, out, source=None, sbom=_sbom(tmp_path))) == 0
    assert seen["purls"] == ["pkg:pypi/requests@2.19.0"]  # never the RPM-installed urllib3
    meta = json.loads(out.read_text())["metadata"]
    assert meta["source"] == "osv-scanner"
    assert meta["skipped_os_installed"] == 1


def test_air_gapped_sbom_scan_without_a_database_fails(tmp_path, monkeypatch):
    from traust_engine.adapters import osv_sbom

    _access(monkeypatch, "air-gapped")
    monkeypatch.setattr(
        osv_sbom,
        "run_offline",
        lambda *a: (
            SimpleNamespace(
                stdout='{"results": []}', stderr="unable to fetch OSV database", returncode=127
            ),
            "osv-scanner",
        ),
    )
    out = tmp_path / "o.json"
    assert adapters.call_osv(None, _args(None, out, source=None, sbom=_sbom(tmp_path))) == 2
    assert json.loads(out.read_text())["metadata"]["status"] == "failed"


def test_grype_without_sbom_is_a_usage_error(tmp_path):
    assert (
        adapters.call_osv(None, _args(tmp_path, tmp_path / "o.json", grype=tmp_path / "g.json"))
        == 2
    )


def _deps_dev(monkeypatch, settings):
    from traust.registry import osv_urls

    monkeypatch.setattr(osv_urls, "deps_dev_settings", lambda: settings)


def test_deps_dev_is_on_by_default(monkeypatch):
    from traust_engine.depsdev import DepsDevClient

    _deps_dev(monkeypatch, ("https://api.deps.dev/v3/systems/{ident}", "api"))
    r = adapters._deps_dev_resolver(None, SimpleNamespace(timeout=5))
    assert isinstance(r, DepsDevClient)
    assert r.base_url == "https://api.deps.dev/v3"


def test_deps_dev_opt_out(monkeypatch):
    _deps_dev(monkeypatch, ("https://api.deps.dev/v3/systems/{ident}", "disabled"))
    assert adapters._deps_dev_resolver(None, SimpleNamespace(timeout=5)) is None


def test_a_config_without_deps_dev_says_so(monkeypatch, capsys):
    _deps_dev(monkeypatch, None)
    assert adapters._deps_dev_resolver(None, SimpleNamespace(timeout=5)) is None
    assert "no deps_dev source" in capsys.readouterr().err


def test_the_shipped_feeds_yaml_enables_deps_dev_with_its_license():
    from traust.paths import HARNESS_ROOT
    from traust.registry import feeds_config

    spec = feeds_config.load(HARNESS_ROOT / "config" / "feeds.yaml")["deps_dev"]
    assert spec["access"] == "api"
    assert spec["license"]["id"] == "CC-BY-4.0"
    assert "Google APIs Terms of Service" in spec["license"]["terms"]


def test_resolution_is_reported(tmp_path, monkeypatch, capsys):
    from traust_engine.adapters import osv as osv_mod

    seen = {}

    def fake_scan(repo, client, resolver=None):
        seen["resolver"] = resolver
        return _body(
            "complete",
            transitive_coverage="partial",
            unresolved_manifests=[{"path": "pom.xml", "reason": {"deps.dev not-found": 1}}],
            resolution={"status": "complete", "manifests_resolved": 3, "packages_added": 40},
        )

    _deps_dev(monkeypatch, ("https://api.deps.dev/v3/systems/{ident}", "api"))
    monkeypatch.setattr(osv_mod, "scan_api", fake_scan)
    assert adapters.call_osv(None, _args(tmp_path, tmp_path / "o.json")) == 0
    assert seen["resolver"] is not None
    err = capsys.readouterr().err
    assert "deps.dev resolved 3 manifest(s)" in err
    assert "still unresolved" in err
