"""`traust impact package`: one `ExposureService.package_advisories` call, on traust-core in-process
on SQLite with the advisory source stubbed (secure-rpm-audit's OSV-by-package lookup)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_impact_doors import LODASH, Lookup, home, run
from traust.cli import impact
from traust.cli.__main__ import main

__all__ = ["home"]


@pytest.fixture(autouse=True)
def hits(monkeypatch: pytest.MonkeyPatch) -> dict:
    listed: dict = {}
    monkeypatch.setattr(Lookup, "hits", listed)
    return listed


def test_package_lists_the_advisories_on_that_version(home: Path, hits: dict) -> None:
    hits["npm/lodash@4.17.20"] = (LODASH.identifier, "NOT-AN-ID", "GHSA-xxxx-xxxx-xxxx")
    rc, out = run(impact.package, home, "lodash", "4.17.20", "--ecosystem", "npm")
    assert rc == 0
    found = json.loads(out)
    assert found["package"] == "npm/lodash@4.17.20"
    assert [a["identifier"] for a in found["advisories"]] == [LODASH.identifier]
    assert found["rejected"] == ["NOT-AN-ID"]
    assert found["details_missing"] == 1


def test_package_with_none_listed_is_an_answer(home: Path) -> None:
    rc, out = run(impact.package, home, "lodash", "4.17.21", "--ecosystem", "npm")
    assert rc == 0
    assert json.loads(out)["advisories"] == []


def test_an_unanswered_query_is_a_gap_not_clean(
    home: Path, hits: dict, capsys: pytest.CaptureFixture[str]
) -> None:
    hits["npm/lodash@4.17.20"] = None
    rc, out = run(impact.package, home, "lodash", "4.17.20", "--ecosystem", "npm")
    assert (rc, out) == (2, "")
    assert "did not answer" in capsys.readouterr().err


def test_an_ecosystem_the_source_cannot_name_is_refused(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _ = run(impact.package, home, "openssl", "3.0.7", "--ecosystem", "rpm")
    assert rc == 2
    assert "can't answer rpm" in capsys.readouterr().err


def test_an_unknown_ecosystem_is_a_usage_error(home: Path) -> None:
    with pytest.raises(SystemExit) as exit_:
        run(impact.package, home, "lodash", "4.17.20", "--ecosystem", "Go")
    assert exit_.value.code == 2


def test_the_impact_group_routes_package(home: Path, hits: dict, capsys) -> None:
    hits["npm/lodash@4.17.20"] = (LODASH.identifier,)
    argv = ["impact", "package", "--config-home", str(home), "lodash", "4.17.20"]
    assert main([*argv, "--ecosystem", "npm"]) == 0
    assert json.loads(capsys.readouterr().out)["package"] == "npm/lodash@4.17.20"
