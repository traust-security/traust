from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from traust_core.v1.context import ArtifactsConfig, Config, Context, DatabaseConfig
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.findings import Finding, Location, Occurrence
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.vocabulary import ScannerSeverity
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from tests.test_products_doors import _postgres
from traust.cli import critical_misses

NOW = datetime(2026, 10, 20, tzinfo=UTC)
START = datetime(2026, 10, 1, tzinfo=UTC)
END = datetime(2026, 11, 1, tzinfo=UTC)
WINDOW = ["--start", START.isoformat(), "--end", END.isoformat()]
HOSTILE = "a | b `tick` <img src=x onerror=alert(1)> [docs](javascript:alert(1))\n## forged"


@pytest.fixture(params=["sqlite", "postgres"])
def core(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Context]:
    with contextlib.ExitStack() as stack:
        database = (
            DatabaseConfig(url=stack.enter_context(_postgres()))
            if request.param == "postgres"
            else DatabaseConfig()
        )
        context = Context(
            Config(
                home=tmp_path / "store",
                artifacts=ArtifactsConfig(path=tmp_path / "artifacts"),
                database=database,
            ),
            clock=FixedClock(NOW),
        )
        monkeypatch.setattr(critical_misses, "load", lambda _: context)
        yield context
        context.database.dispose()


def seed_misses(core: Context) -> tuple[UUID, UUID]:
    with SqlTraustUnitOfWork(core.database) as uow:
        repository = uow.repositories.add(
            Repository(url="https://github.com/example/audited", public=True)
        )
        ref = uow.repository_refs.add(
            RepositoryRef(repository_id=repository.id, sha="a" * 40, name="main", kind="branch")
        )

        def assessment(at: datetime, kind: AssessmentKind) -> Assessment:
            return uow.assessments.add(
                Assessment(
                    repository_ref_id=ref.id,
                    kind=kind,
                    status="completed",
                    assessor="tool:fixture",
                    assessor_version="1",
                    occurred_at=at,
                )
            )

        def finding(
            title: str, fingerprint: str, run: Assessment, severity: ScannerSeverity, path: str
        ) -> None:
            saved = uow.findings.add(
                Finding(
                    repository_id=repository.id,
                    fingerprint_algo="v3",
                    fingerprint=fingerprint * 64,
                    title=title,
                )
            )
            occurrence = uow.occurrences.add(
                Occurrence(finding_id=saved.id, assessment_id=run.id, severity=severity)
            )
            uow.locations.add(
                Location(occurrence_id=occurrence.id, path=path, line_start=1, line_end=1)
            )

        prior = assessment(START - timedelta(days=1), AssessmentKind.SECURE_CODE)
        finding("Prior area", "a", prior, ScannerSeverity.HIGH, "pkg/area.go")
        discovered = assessment(START + timedelta(days=4), AssessmentKind.SCANNER)
        finding(HOSTILE, "b", discovered, ScannerSeverity.CRITICAL, "pkg/new.go")
        area = assessment(START + timedelta(days=5), AssessmentKind.SCANNER)
        finding("Already reported area", "c", area, ScannerSeverity.CRITICAL, "pkg/area.go")
        excluded = assessment(END, AssessmentKind.SCANNER)
        finding("At exclusive end", "d", excluded, ScannerSeverity.CRITICAL, "pkg/end.go")
        uow.commit()
    assert prior.id is not None and discovered.id is not None
    return prior.id, discovered.id


def test_cli_publishes_empty_reports_without_changing_the_json_array(
    core: Context, tmp_path: Path
) -> None:
    out = tmp_path / "data" / "critical.json"
    assert critical_misses.main(["--json-out", str(out), *WINDOW]) == 0
    assert json.loads(out.read_bytes()) == []
    assert out.with_suffix(".md").is_file()
    assert out.with_suffix(".html").is_file()


def test_default_reports_are_materialized_under_the_results_tree(
    core: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results = tmp_path / "results"
    monkeypatch.setattr(critical_misses, "analysis_results_dir", lambda _: results)
    assert critical_misses.main(WINDOW) == 0
    assert {path.name for path in results.iterdir()} == {
        "CRITICAL-MISSES.json",
        "CRITICAL-MISSES.md",
        "CRITICAL-MISSES.html",
    }
    assert json.loads((results / "CRITICAL-MISSES.json").read_bytes()) == []


def test_native_publication_preserves_population_provenance_and_safe_human_outputs(
    core: Context, tmp_path: Path
) -> None:
    prior, discovered = seed_misses(core)
    json_out = tmp_path / "data" / "critical.native.json"
    markdown_out = tmp_path / "reports" / "critical.native.md"
    assert (
        critical_misses.main(["--json-out", str(json_out), "--out", str(markdown_out), *WINDOW])
        == 0
    )
    document = json.loads(json_out.read_bytes())
    assert [row["title"] for row in document] == [HOSTILE, "Already reported area"]
    assert [row["reason"] for row in document] == ["missed", "area_reported"]
    assert document[0]["found_by"] == str(discovered)
    assert {row["missed_by"] for row in document} == {str(prior)}
    assert all(row["validity"] is None for row in document)
    markdown = markdown_out.read_text()
    html = markdown_out.with_suffix(".html").read_text()
    for finding in document:
        for identity in (
            finding["finding_id"],
            finding["repository_id"],
            finding["found_by"],
            finding["missed_by"],
        ):
            assert identity in markdown and identity in html
    assert "<img" not in markdown and "<img" not in html
    assert "[docs](javascript:" not in markdown
    assert "\n## forged" not in markdown
    assert "At exclusive end" not in markdown and "At exclusive end" not in html


@pytest.mark.parametrize(
    "window",
    [
        ["--start", START.isoformat()],
        ["--start", "2026-10-01T00:00:00", "--end", "2026-11-01T00:00:00"],
        ["--start", END.isoformat(), "--end", START.isoformat()],
        ["--start", START.isoformat(), "--end", START.isoformat()],
    ],
)
def test_invalid_windows_refuse_before_creating_any_report(
    core: Context, tmp_path: Path, window: list[str]
) -> None:
    destination = tmp_path / "export" / "critical.json"
    assert critical_misses.main(["--json-out", str(destination), *window]) == 2
    assert not destination.parent.exists()


@pytest.mark.parametrize("alias", ["same", "relative", "symlink"])
def test_output_collisions_do_not_overwrite_existing_data(
    core: Context, tmp_path: Path, alias: str
) -> None:
    destination = tmp_path / "critical.json"
    destination.write_bytes(b"original evidence")
    if alias == "symlink":
        markdown = tmp_path / "alias.md"
        markdown.symlink_to(destination)
    elif alias == "relative":
        child = tmp_path / "child"
        child.mkdir()
        markdown = child / ".." / destination.name
    else:
        markdown = destination
    assert (
        critical_misses.main(["--json-out", str(destination), "--out", str(markdown), *WINDOW]) == 2
    )
    assert destination.read_bytes() == b"original evidence"
    assert not markdown.with_suffix(".html").exists()
