from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from traust_core.v1.context import Context
from traust_core.v1.models.values import HttpsRepoUrl

from tests.test_assessment_record import core_home as core_home
from traust.cli import assessment_record
from traust.cli.__main__ import main as cli

URL = "https://github.com/example/widget-operator"


def record_profile(home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> str:
    path = tmp_path / "profile.json"
    path.write_text(
        json.dumps(
            {
                "repo": "widget-operator",
                "summary": {"workloads": 1, "rbac_rules": 0},
            }
        )
    )
    rc = assessment_record.main(
        [
            "--config-home",
            str(home),
            str(path),
            "--kind",
            "priv_profile",
            "--repo-url",
            URL,
            "--sha",
            "a" * 40,
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert rc == 0
    return output["id"]


def test_grouped_draft_is_unsigned_and_does_not_promote_a_branch_only_profile(
    core_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record_profile(core_home, tmp_path, capsys)
    assert (
        cli(
            [
                "portfolio",
                "crown-jewel-draft",
                "--config-home",
                str(core_home),
                "--tier1-size",
                "1",
            ]
        )
        == 0
    )
    draft = json.loads(capsys.readouterr().out)
    assert draft["status"] == "draft-unsigned"
    assert draft["dispatch_allowed"] is False
    assert draft["universe_repositories"] == 1
    assert draft["tier1_size"] == 1
    assert draft["tiers"] == {"tier1": [], "tier2": [], "watch": []}
    assert draft["repositories"][0]["repository_url"] == URL
    assert draft["repositories"][0]["components"]["privilege_tier"] is None
    assert draft["repositories"][0]["ownership_gap"] is True
    portfolio = Context.from_file(core_home / "traust.yaml").services().portfolio
    registered = portfolio.find_repository(HttpsRepoUrl.parse(URL, ("github.com",)))
    assert registered is not None
    assert draft["repositories"][0]["repository_id"] == str(registered.id)


def test_grouped_org_index_writes_navigation_and_retains_assessment_artifact_provenance(
    core_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assessment_id = record_profile(core_home, tmp_path, capsys)
    out = tmp_path / "index"
    assert (
        cli(
            [
                "portfolio",
                "org-index",
                "--config-home",
                str(core_home),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    paths = {Path(path).suffix: Path(path) for path in result["written"]}
    assert set(paths) == {".json", ".md", ".html"}
    index = json.loads(paths[".json"].read_text())
    [organization] = index["organizations"]
    assert (organization["host"], organization["namespace"]) == ("github.com", "example")
    [repository] = organization["repositories"]
    assert repository["repository_url"] == URL
    [assessment] = repository["assessments"]
    assert assessment["assessment"]["id"] == assessment_id
    [artifact] = assessment["artifacts"]
    assert artifact["kind"] == "operator-priv-profile"
    [stored] = (
        Context.from_file(core_home / "traust.yaml")
        .services()
        .artifacts.list_for_assessment(UUID(assessment_id))
    )
    assert artifact["digest"] == stored.digest
    assert artifact["uri"] == stored.uri
    assert artifact["artifact_id"] == str(stored.id)
    assert artifact["uri"] in paths[".md"].read_text()
    assert f'href="{URL}"' in paths[".html"].read_text()


def test_iac_census_counts_profile_only_repositories_as_never_code_audited(
    core_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record_profile(core_home, tmp_path, capsys)
    assert cli(["portfolio", "iac-census", "--config-home", str(core_home)]) == 0
    census = json.loads(capsys.readouterr().out)
    assert census["population"] == census["observed"] == 0
    assert len(census["never_audited"]) == 1
    assert census["worklist"] == census["repositories"] == []


def test_draft_rejects_a_pilot_larger_than_the_total_tier(
    core_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        cli(
            [
                "portfolio",
                "crown-jewel-draft",
                "--config-home",
                str(core_home),
                "--tier1-size",
                "101",
            ]
        )
        == 2
    )
    assert capsys.readouterr().out == ""
