"""Real grouped CLI, OSV parsing, SQLite and native impact documents at the HTTP boundary."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import urllib.parse
import urllib.request
import urllib.response
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.dependencies import ImpactFilter

from traust.cli.__main__ import main
from traust.context import load

GHSA = "GHSA-aaaa-bbbb-cccc"
GO = "GO-2099-0001"
CVE = "CVE-2099-0001"
A, B = "example.com/alias-a", "example.com/alias-b"


def affected(name: str, introduced: str, fixed: str | None) -> dict[str, Any]:
    events = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "package": {"ecosystem": "Go", "name": name},
        "ranges": [{"type": "SEMVER", "events": events}],
    }


def records(merged: bool, fix_a: bool) -> dict[str, Any]:
    first = {
        "id": GHSA,
        "aliases": [CVE],
        "database_specific": {"severity": "CRITICAL"},
        "affected": [affected(A, "1.0.0", "1.1.0" if fix_a else None)],
    }
    second = {
        "id": GO,
        "aliases": [CVE],
        "database_specific": {"severity": "HIGH"},
        "affected": [affected(B, "2.0.0", "2.2.0")],
    }
    if merged:
        first["affected"].append(copy.deepcopy(second["affected"][0]))
    return {GHSA: first, GO: second}


class OsvTransport:
    def __init__(self, documents: dict[str, Any]) -> None:
        self.documents = documents

    def open(self, request: urllib.request.Request, **_: Any) -> Any:
        url = urllib.parse.urlparse(request.full_url)
        assert url.scheme == "https" and url.netloc == "api.osv.dev"
        if request.get_method() == "POST" and url.path == "/v1/querybatch":
            queries = json.loads(request.data)["queries"]
            hits = {(A, "1.0.5"): [GHSA], (B, "2.0.5"): [GO], (B, "2.3.0"): []}
            answer = {
                "results": [
                    {"vulns": [{"id": i} for i in hits[(q["package"]["name"], q["version"])]]}
                    for q in queries
                ]
            }
        else:
            assert request.get_method() == "GET" and url.path.startswith("/v1/vulns/")
            identifier = urllib.parse.unquote(url.path.removeprefix("/v1/vulns/"))
            answer = self.documents[GHSA if identifier == CVE else identifier]
        return urllib.response.addinfourl(
            io.BytesIO(json.dumps(answer).encode()), {}, request.full_url, 200
        )


def invoke(home: Path, op: str, *args: str) -> tuple[int, dict[str, Any]]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = main(["impact", op, "--config-home", str(home), *args])
    return code, json.loads(output.getvalue()) if code == 0 else {}


def seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "config"
    home.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    for name, package, version, sha in [
        ("a", A, "1.0.5", "a" * 40),
        ("b-in", B, "2.0.5", "b" * 40),
        ("b-out", B, "2.3.0", "c" * 40),
    ]:
        sbom = tmp_path / f"{name}.json"
        sbom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "components": [{"purl": f"pkg:golang/{package}@{version}"}],
                }
            )
        )
        code, _ = invoke(
            home,
            "sbom",
            str(sbom),
            "--repo-url",
            f"https://github.com/alias-proof/{name}",
            "--sha",
            sha,
        )
        assert code == 0
    return home


def assert_documents(home: Path, fix_a: bool) -> None:
    services = load(home).services()
    analyses = services.exposure.impacts(ImpactFilter(), PageRequest(limit=50)).items
    documents = [json.loads(services.artifacts.payload(a.artifact_id)) for a in analyses]
    by_repo = {doc["repos"][0]["repo"].rsplit("/", 1)[-1]: doc for doc in documents}
    assert set(by_repo) == {"a", "b-in", "b-out"}
    assert len(documents) == 3
    assert by_repo["a"]["metadata"]["module"] == A
    assert by_repo["a"]["metadata"]["fixed_version"] == ("1.1.0" if fix_a else None)
    for name, version in (("b-in", "2.0.5"), ("b-out", "2.3.0")):
        doc = by_repo[name]
        assert (doc["metadata"]["module"], doc["metadata"]["ecosystem"]) == (B, "go")
        assert doc["metadata"]["vulnerable_range"] == ">=2.0.0 <2.2.0"
        assert doc["repos"][0]["version"] == version
    assert by_repo["b-in"]["metadata"]["fixed_version"] == "2.2.0"
    assert by_repo["b-in"]["repos"][0]["classification"] == "inconclusive"
    assert by_repo["b-out"]["repos"][0]["classification"] == "version_not_in_range"


@pytest.mark.parametrize(
    "merged,fix_a", [(False, True), (True, True), (False, False), (True, False)]
)
def test_sweep_generated_analyze_preserves_disjoint_alias_ranges_and_fixes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    merged: bool,
    fix_a: bool,
) -> None:
    transport = OsvTransport(records(merged, fix_a))
    monkeypatch.setattr(urllib.request, "urlopen", transport.open)
    home = seed(tmp_path, monkeypatch)
    code, worklist = invoke(home, "sweep", "--min-severity", "high", "--deep-scan-cap", "0")
    assert code == 0
    [row] = worklist["advisories"]
    assert (row["display_id"], row["fix_available"]) == (CVE, True)
    assert set(row["packages"]) == {f"go/{A}", f"go/{B}"}
    code, result = invoke(home, *row["impact_argv"][4:])
    assert code == 0 and (result["commits"], result["analyses"]) == (3, 3)
    assert_documents(home, fix_a)


def test_exported_advisory_input_analyzes_every_alias_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def offline(*_: Any, **__: Any) -> None:
        raise AssertionError("offline analysis must not open the network")

    monkeypatch.setattr(urllib.request, "urlopen", offline)
    home = seed(tmp_path, monkeypatch)
    arguments = []
    for identifier, record in records(False, False).items():
        path = tmp_path / f"{identifier}.json"
        path.write_text(json.dumps(record))
        arguments += ["--advisory-file", str(path)]
    code, found = invoke(home, "find", GHSA, *arguments)
    assert code == 0
    assert {p["name"] for p in found["affected"]} == {A, B}
    code, result = invoke(home, "analyze", GHSA, *arguments)
    assert code == 0 and result["analyses"] == 3
    assert_documents(home, False)
    code, worklist = invoke(
        home,
        "sweep",
        "--min-severity",
        "high",
        "--deep-scan-cap",
        "0",
        *arguments,
    )
    assert code == 0
    [row] = worklist["advisories"]
    assert row["impact_argv"][-len(arguments) :] == arguments
    assert invoke(home, *row["impact_argv"][4:])[0] == 0


def test_unknown_or_malformed_export_never_records_an_impact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = seed(tmp_path, monkeypatch)
    exported = tmp_path / "advisory.json"
    exported.write_text(json.dumps(records(False, True)[GHSA]))
    assert invoke(home, "analyze", "CVE-2099-9999", "--advisory-file", str(exported))[0] == 2
    exported.write_text("{broken")
    assert invoke(home, "analyze", GHSA, "--advisory-file", str(exported))[0] == 2
    assert load(home).services().exposure.impacts(ImpactFilter(), PageRequest()).items == ()
