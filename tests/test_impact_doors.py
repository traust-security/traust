"""`traust impact find|sbom|symbols|analyze|sweep` end to end on traust-core, in-process on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.models.dependencies import (
    AdvisoryHits,
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    PackageVersion,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_core.v1.providers.forge_archive import ArchiveCheckout
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.osv import OsvAdvisoryLookup
from traust_core.v1.providers.sources import CheckoutRequest, Workspace
from traust_core.v1.providers.syft import MANIFESTS, SyftSbom
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from traust.cli import check_fix_propagation, impact
from traust.context import load

SHA = "a" * 40
REPO = "https://github.com/org/app"
LODASH = AdvisoryRecord(
    identifier=AdvisoryIdentifier("GHSA-35jh-r3h4-6jhm"),
    affected=(
        AffectedPackage(
            ecosystem=Ecosystem.NPM,
            name="lodash",
            spans=(AffectedSpan(introduced=Version("0"), fixed=Version("4.17.21")),),
        ),
    ),
    declared_severity="HIGH",
    source="https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm",
)


class Lookup:
    name = "osv"
    ecosystems = OsvAdvisoryLookup.ecosystems
    hits: dict[str, tuple[str, ...] | None] = {}

    def check(self) -> Readiness:
        return Readiness(ready=True)

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        found = LODASH if identifier == LODASH.identifier else None
        return Result(found, Acquisition(provider="osv", acquired_at=datetime.now(UTC)))

    def affecting(self, queries: list[PackageVersion]) -> Result[AdvisoryHits]:
        ids = tuple(self.hits.get(str(q), ()) for q in queries)
        issues = {"unreachable": sum(i is None for i in ids)} if None in ids else {}
        hits = AdvisoryHits(ids=ids, issues=issues)
        return Result(hits, Acquisition(provider="osv", acquired_at=datetime.now(UTC)))


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))

    def core(config_home: Path | None) -> Any:
        made = load(config_home)
        made.advisories = Lookup()
        return made

    monkeypatch.setattr(impact, "_core", core)
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = door(["--config-home", str(home), *argv])
    return rc, out.getvalue()


def sbom(tmp_path: Path, version: str) -> Path:
    path = tmp_path / f"sbom-{version}.json"
    components = [{"purl": f"pkg:npm/lodash@{version}"}]
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}))
    return path


def test_find_prints_the_advisory_from_its_source(home: Path) -> None:
    rc, out = run(impact.find, home, LODASH.identifier)
    assert rc == 0
    found = json.loads(out)
    assert (found["identifier"], found["affected"][0]["name"]) == (LODASH.identifier, "lodash")
    assert found["advisory_id"]


def test_an_advisory_its_source_doesnt_know_is_not_assessed(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(impact.analyze, home, "CVE-2099-0001")[0] == 2
    assert "not assessed" in capsys.readouterr().err
    assert run(impact.find, home, "../etc")[0] == 2


def test_analyze_records_every_commit_the_sboms_reach(home: Path, tmp_path: Path) -> None:
    rc, out = run(
        impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA
    )
    assert rc == 0 and json.loads(out)["sbom_id"]
    other = "https://github.com/org/web"
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.21")), "--repo-url", other, "--sha", "b" * 40)
    rc, out = run(impact.analyze, home, LODASH.identifier)
    assert rc == 0
    summary = json.loads(out)
    assert summary["commits"] == 2
    assert summary["classifications"] == {"likely_affected": 1, "version_not_in_range": 1}
    assert summary["affected"] == []
    assert json.loads(run(impact.analyze, home, LODASH.identifier)[1]) == summary


def test_scan_checks_out_an_undecided_commit_at_its_sha_through_the_service(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA)
    asked: list[CheckoutRequest] = []
    released: list[Path] = []

    def checkout(self: MirrorCheckout, request: CheckoutRequest) -> Result[Workspace]:
        asked.append(request)
        path = tmp_path / "repo"
        path.mkdir()
        (path / "a.js").write_text("const _ = require('lodash')\n")
        return Result(
            Workspace(repo=request.repo, sha=request.ref, path=path, provider=self.name),
            Acquisition(provider=self.name, acquired_at=datetime.now(UTC)),
        )

    def release(self: MirrorCheckout, workspace: Workspace) -> None:
        released.append(workspace.path)

    monkeypatch.setattr(MirrorCheckout, "checkout", checkout)
    monkeypatch.setattr(MirrorCheckout, "release", release)
    rc, out = run(impact.analyze, home, LODASH.identifier, "--scan")
    assert rc == 0
    assert [(str(a.repo), str(a.ref)) for a in asked] == [(REPO, SHA)]
    assert released == [tmp_path / "repo"]
    assert json.loads(out)["classifications"] == {"likely_affected": 1}


def test_one_commit_by_url_and_sha(home: Path, tmp_path: Path) -> None:
    unrelated = tmp_path / "sbom-unrelated.json"
    unrelated.write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": [{"purl": "pkg:npm/left-pad@1.3.0"}]})
    )
    run(impact.sbom, home, str(unrelated), "--repo-url", REPO, "--sha", SHA)
    rc, out = run(impact.analyze, home, LODASH.identifier, "--repo-url", REPO, "--sha", SHA)
    # an SBOM given as a document has no manifest scan behind it, so its coverage is unknown
    # and a package it lacks can't be called not imported (contracts manifest-coverage binding)
    assert rc == 0 and json.loads(out)["classifications"] == {"inconclusive": 1}
    with pytest.raises(SystemExit):
        run(impact.analyze, home, LODASH.identifier, "--repo-url", REPO)


def test_symbols_says_why_when_unresolved(home: Path) -> None:
    rc, out = run(impact.symbols, home, LODASH.identifier)
    assert rc == 0 and json.loads(out)["status"] == "no_fix_commit"


def test_fix_propagation_reads_the_commits_sbom(home: Path, tmp_path: Path) -> None:
    args = ["--repo-url", REPO, "--sha", SHA, "--ecosystem", "npm", "--module", "lodash"]
    rc, out = run(check_fix_propagation.main, home, *args, "--fixed-version", "4.17.21")
    assert rc == 0 and json.loads(out)["propagation"] == "not_observed"
    rc, out = run(
        check_fix_propagation.main,
        home,
        *args,
        "--fixed-version",
        "4.17.21",
        "--sbom",
        str(sbom(tmp_path, "4.17.20")),
    )
    assert json.loads(out)["propagation"] == "pending"
    assert json.loads(out)["checked"] == [
        {"source": "manifest", "version": "4.17.20", "consumed": False}
    ]


def test_judged_symbols_and_the_feature_description_reach_the_record(
    home: Path, tmp_path: Path
) -> None:
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA)
    rc, _ = run(
        impact.analyze,
        home,
        LODASH.identifier,
        "--repo-url",
        REPO,
        "--sha",
        SHA,
        "--symbols",
        "lodash.template, lodash.merge",
        "--feature-desc",
        "templates rendered from user input",
    )
    assert rc == 0
    core = load(home)
    with SqlTraustUnitOfWork(core.database) as uow:
        repo = uow.repositories.find_by_url(REPO)
        assert repo is not None and repo.id is not None
        [ref] = uow.repository_refs.list_for(repo.id)
        assert ref.id is not None
        [assessment] = [a for a in uow.assessments.list_for_ref(ref.id) if a.kind == "impact"]
        assert assessment.id is not None
        [artifact] = uow.artifacts.list_for_assessment(assessment.id)
    doc = json.loads((core.config.artifacts_path() / artifact.uri).read_text())
    assert doc["metadata"]["vulnerable_symbols"] == ["lodash.template", "lodash.merge"]
    assert doc["metadata"]["feature_description"] == "templates rendered from user input"


@pytest.mark.parametrize(
    ("hits", "code", "status"),
    [
        ({"npm/lodash@4.17.20": (LODASH.identifier,)}, 0, "complete"),
        ({"npm/lodash@4.17.20": None, "npm/lodash@4.17.21": ()}, 3, "degraded"),
        ({"npm/lodash@4.17.20": None, "npm/lodash@4.17.21": None}, 2, "failed"),
    ],
)
def test_sweep_lists_advisories_with_their_analyze_argv_and_exits_by_status(
    home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hits: dict[str, tuple[str, ...] | None],
    code: int,
    status: str,
) -> None:
    monkeypatch.setattr(Lookup, "hits", hits)
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA)
    other = "https://github.com/org/web"
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.21")), "--repo-url", other, "--sha", "b" * 40)
    out = tmp_path / "out" / "worklist.json"
    rc, printed = run(impact.sweep, home, "--min-severity", "high", "--out", str(out))
    swept = json.loads(printed)
    assert (rc, swept["status"]) == (code, status)
    assert json.loads(out.read_text()) == swept
    if status == "complete":
        [row] = swept["advisories"]
        assert (row["identifier"], row["commits"], row["severity"]) == (
            LODASH.identifier,
            1,
            "high",
        )
        assert row["impact_argv"] == [
            "python3",
            "-m",
            "traust.cli",
            "impact",
            "analyze",
            LODASH.identifier,
            "--scan",
        ]


def test_sweep_over_the_cap_is_sbom_only_and_ecosystems_are_checked(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Lookup, "hits", {"npm/lodash@4.17.20": (LODASH.identifier,)})
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA)
    rc, printed = run(impact.sweep, home, "--min-severity", "low", "--deep-scan-cap", "0")
    [row] = json.loads(printed)["advisories"]
    assert rc == 0 and row["impact_argv"][-1] == LODASH.identifier
    assert json.loads(run(impact.sweep, home, "--ecosystem", "Go")[1])["status"] == "failed"
    with pytest.raises(SystemExit):
        run(impact.sweep, home, "--ecosystem", "cobol")


def test_sbom_without_a_document_reads_the_commits_manifests(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[CheckoutRequest] = []

    def checkout(self: Any, request: CheckoutRequest) -> Result[Workspace]:
        asked.append(request)
        when = datetime.now(UTC)
        workspace = Workspace(repo=request.repo, sha=request.ref, path=tmp_path, provider=self.name)
        return Result(workspace, Acquisition(provider="forge-archive", acquired_at=when))

    def acquire(self: Any, request: Any) -> Result[bytes]:
        raw = sbom(tmp_path, "4.17.20").read_bytes()
        when = datetime.now(UTC)
        return Result(raw, Acquisition(provider="syft", acquired_at=when, version="1.51.1"))

    monkeypatch.setattr(SyftSbom, "check", lambda self: Readiness(ready=True))
    monkeypatch.setattr(SyftSbom, "acquire", acquire)
    monkeypatch.setattr(ArchiveCheckout, "checkout", checkout)
    monkeypatch.setattr(ArchiveCheckout, "release", lambda self, workspace: None)
    rc, out = run(impact.sbom, home, "--repo-url", REPO, "--sha", SHA)
    done = json.loads(out)
    assert rc == 0 and done["sbom_id"]
    [request] = asked
    assert (str(request.repo), str(request.ref), request.keep) == (REPO, SHA, MANIFESTS)


def test_a_commit_keeps_the_first_sbom_recorded_for_it(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a later `impact sbom` without a file returns the document SBOM, never a scan of it
    rc, out = run(
        impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA
    )
    assert rc == 0

    def no_scan(*_: object, **__: object) -> Any:
        raise AssertionError("a commit with a recorded SBOM was fetched or scanned")

    for provider in (ArchiveCheckout, MirrorCheckout):
        monkeypatch.setattr(provider, "checkout", no_scan)
    monkeypatch.setattr(SyftSbom, "acquire", no_scan)
    rc, again = run(impact.sbom, home, "--repo-url", REPO, "--sha", SHA)
    assert rc == 0 and json.loads(again)["sbom_id"] == json.loads(out)["sbom_id"]
