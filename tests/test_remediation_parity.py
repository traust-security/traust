"""Remediation selectors and worklists through the real local Core services."""

from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.inventory import RefName, Repository
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import RefKind

from traust.cli import findings, remediation


@pytest.fixture
def core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Context:
    context = Context(Config(home=tmp_path / "store", remediation={"fork_org": "private-mirrors"}))
    monkeypatch.setattr(remediation, "load", lambda _: context)
    monkeypatch.setattr(findings, "load", lambda _: context)
    return context


def invoke(operation: Callable[[list[str]], int], *arguments: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = operation(list(arguments))
    return status, stdout.getvalue(), stderr.getvalue()


def register(core: Context, name: str) -> Repository:
    return core.services().portfolio.register_repository(
        HttpsRepoUrl.parse(f"https://github.com/example-org/{name}", ["github.com"]), True
    )


def test_rollup_cli_uses_only_matched_registered_targets(core: Context, tmp_path: Path) -> None:
    selected, other = register(core, "selected"), register(core, "other")
    progress = tmp_path / "PROGRESS.md"
    progress.write_text(
        "| 1 | example-org/selected | boundary campaign |\n| 2 | example-org/other | unrelated |\n"
    )
    status, stdout, stderr = invoke(
        remediation.fleet_targets, "--rollup", "boundary", "--progress", str(progress)
    )
    assert (status, stderr) == (0, "")
    targets = json.loads(stdout)
    assert [(t["repository_id"], t["url"]) for t in targets] == [(str(selected.id), selected.url)]
    assert str(other.id) not in {t["repository_id"] for t in targets}
    assert targets[0]["evidence"] == "PROGRESS.md rollup match: /boundary/"
    status, stdout, _ = invoke(
        remediation.fleet_targets, "--rollup", "absent", "--progress", str(progress)
    )
    assert (status, json.loads(stdout)) == (0, [])
    progress.write_text("| 1 | missing/target | boundary campaign |\n")
    status, stdout, _ = invoke(
        remediation.fleet_targets, "--rollup", "boundary", "--progress", str(progress)
    )
    assert (status, stdout) == (2, "")


def test_fork_list_cli_enumerates_known_policy_mappings(core: Context) -> None:
    first, second = register(core, "first"), register(core, "second")
    status, stdout, stderr = invoke(remediation.fork, "--list")
    assert (status, stderr) == (0, "")
    mappings = {row["repository_id"]: row for row in json.loads(stdout)}
    assert set(mappings) == {str(first.id), str(second.id)}
    assert {row["fork"]["url"] for row in mappings.values()} == {
        "https://github.com/private-mirrors/first",
        "https://github.com/private-mirrors/second",
    }
    assert all(row["unavailable_reason"] is None for row in mappings.values())


def test_sweep_cli_writes_branch_aware_json_and_markdown_from_real_services(
    core: Context, tmp_path: Path
) -> None:
    repository = register(core, "service")
    ref = core.services().portfolio.register_ref(
        repository.id, GitSha.parse("b" * 40), RefName("release-1"), RefKind.BRANCH
    )
    output = tmp_path / "sweep.json"
    status, stdout, stderr = invoke(
        remediation.verify_sweep,
        "--repo-url",
        repository.url,
        "--include-branches",
        "--out",
        str(output),
    )
    assert (status, stdout, stderr) == (0, "", "")
    document = json.loads(output.read_text())
    release = next(row for row in document["skipped"] if row["ref_name"] == "release-1")
    assert (release["repository_ref_id"], release["head_sha"], release["skip"]) == (
        str(ref.id),
        "b" * 40,
        "nothing_open",
    )
    assert release["head_source"] == "registered_branch"
    markdown = output.with_suffix(".md").read_text()
    row = next(line for line in markdown.splitlines() if "release-1" in line)
    assert repository.url in row and "b" * 40 in row
    assert document["queued"] == []


def test_branch_baseline_cli_rejects_a_ref_from_another_repository(core: Context) -> None:
    owner, other = register(core, "owner"), register(core, "other")
    ref = core.services().portfolio.register_ref(
        owner.id, GitSha.parse("b" * 40), RefName("release-1"), RefKind.BRANCH
    )
    status, stdout, _ = invoke(findings.baseline, "--repo-url", other.url, "--ref-id", str(ref.id))
    assert (status, stdout) == (2, "")
    status, stdout, stderr = invoke(
        findings.baseline, "--repo-url", owner.url, "--ref-id", str(ref.id)
    )
    assert (status, json.loads(stdout), stderr) == (0, [], "")
