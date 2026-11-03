from __future__ import annotations

import json
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli import pqc
from traust.cli.groups.pqc import PQC

FIXTURE = Path(__file__).parent / "fixtures/pqc/widget-pqc-readiness.json"


def test_repair_cli_validates_a_batch_before_writing_and_never_overwrites_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    body = json.loads(FIXTURE.read_bytes())
    body.pop("remediations")
    for clock in body["clock_items"]:
        clock["remediation_effort"] = None
    original = tmp_path / "widget-pqc-readiness.json"
    original.write_text(json.dumps(body))
    original.with_suffix(".md").write_text(
        "# Report\n\n### Fix now\n- `tls.go:4` — Remove the group pin\n"
    )
    before = original.read_bytes()
    output = tmp_path / "repaired"
    assert pqc.repair(["--report", str(original), "--out-dir", str(output)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result[0]["derived"] is True and result[0]["remediations"] == 2
    assert original.read_bytes() == before
    repaired = json.loads((output / original.name).read_bytes())
    assert [r["category"] for r in repaired["remediations"]] == ["fix-now", "deadline"]
    assert "### What the domains mean" in (output / original.with_suffix(".md").name).read_text()
    assert pqc.repair(["--report", str(original), "--out-dir", str(tmp_path)]) == 2
    capsys.readouterr()
    assert original.read_bytes() == before
    dry_output = tmp_path / "preview"
    assert pqc.repair(["--report", str(original), "--out-dir", str(dry_output), "--dry-run"]) == 0
    assert not dry_output.exists()


def test_worklist_cli_discovers_registered_unassessed_repositories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    services = core.services()
    for slug in ("widget", "oauth-gateway"):
        repository = services.portfolio.register_repository(
            HttpsRepoUrl.parse(f"https://github.com/example/{slug}", ["github.com"]),
            True,
        )
        services.portfolio.register_ref(repository.id, GitSha.parse("a" * 40), None, None)
    assert pqc.worklist([]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert [(e["priority_tier"], e["route"]) for e in entries] == [
        ("chokepoint", "source"),
        ("tail", "source"),
    ]
    assert all(e["scan"]["assessment_id"] is None for e in entries)
    assert pqc.worklist(["--markdown"]) == 0
    markdown = capsys.readouterr().out
    assert "https://github.com/example/oauth-gateway" in markdown
    assert {"repair", "sweep", "worklist"} <= PQC.keys()


def test_repair_batch_with_an_invalid_member_leaves_no_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    bad = tmp_path / "invalid.json"
    bad.write_text("{}")
    output = tmp_path / "output"
    assert (
        pqc.repair(
            [
                "--report",
                str(FIXTURE),
                "--report",
                str(bad),
                "--out-dir",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()


def test_sweep_cli_reports_access_work_and_rejects_invalid_batch_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    core = Context(Config(home=tmp_path / "home"))
    monkeypatch.setattr(pqc, "load", lambda _: core)
    repository = core.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/awaiting-access", ["github.com"]),
        False,
    )
    assert pqc.sweep(["--limit", "1", "--refresh"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["remaining"] == 0 and result["next_cursor"] is None
    assert [
        (r["entry"]["repository_id"], r["status"], r["assessment_id"]) for r in result["results"]
    ] == [(str(repository.id), "access-request", None)]
    assert pqc.sweep(["--limit", "0"]) == 2
    capsys.readouterr()
    assert core.services().portfolio.inventory.list_refs(repository.id) == []
