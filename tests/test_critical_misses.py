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
        [
            "--start",
            START.isoformat(),
            "--end",
            (START + timedelta(days=31, microseconds=1)).isoformat(),
        ],
    ],
)
def test_invalid_windows_refuse_before_creating_any_report(
    core: Context, tmp_path: Path, window: list[str]
) -> None:
    destination = tmp_path / "export" / "critical.json"
    assert critical_misses.main(["--json-out", str(destination), *window]) == 2
    assert not destination.parent.exists()


@pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink"])
def test_output_collisions_do_not_overwrite_existing_data(
    core: Context, tmp_path: Path, alias: str
) -> None:
    destination = tmp_path / "critical.json"
    destination.write_bytes(b"original evidence")
    if alias == "symlink":
        markdown = tmp_path / "alias.md"
        markdown.symlink_to(destination)
    elif alias == "hardlink":
        markdown = tmp_path / "alias.md"
        markdown.hardlink_to(destination)
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


@pytest.mark.parametrize("blocked", ["markdown", "html"])
@pytest.mark.parametrize("existing", [False, True])
def test_invalid_later_destination_preserves_the_entire_report_set(
    core: Context, tmp_path: Path, blocked: str, existing: bool
) -> None:
    paths = {
        "json": tmp_path / "critical.json",
        "markdown": tmp_path / "critical.md",
        "html": tmp_path / "critical.html",
    }
    originals = {}
    for kind, path in paths.items():
        if kind == blocked:
            path.mkdir()
        elif existing:
            originals[path] = f"original {kind}".encode()
            path.write_bytes(originals[path])
    assert critical_misses.main(["--json-out", str(paths["json"]), *WINDOW]) == 2
    for kind, path in paths.items():
        if kind == blocked:
            assert path.is_dir() and list(path.iterdir()) == []
        elif existing:
            assert path.read_bytes() == originals[path]
        else:
            assert not path.exists()


@pytest.mark.parametrize("blocked", ["markdown", "html"])
@pytest.mark.parametrize("existing", [False, True])
def test_failed_later_replacement_rolls_back_the_entire_report_set(
    core: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked: str, existing: bool
) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    paths = {
        "json": report_dir / "critical.json",
        "markdown": report_dir / "critical.md",
        "html": report_dir / "critical.html",
    }
    originals = {}
    if existing:
        for kind, path in paths.items():
            originals[path] = f"original {kind}".encode()
            path.write_bytes(originals[path])
    replace = Path.replace
    failed = False

    def fail_later_destination(source: Path, target: str | Path) -> Path:
        nonlocal failed
        if Path(target) == paths[blocked] and not failed:
            failed = True
            raise PermissionError("destination became unwritable")
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_later_destination)
    assert critical_misses.main(["--json-out", str(paths["json"]), *WINDOW]) == 2
    assert failed
    if existing:
        assert {path: path.read_bytes() for path in paths.values()} == originals
    else:
        assert all(not path.exists() for path in paths.values())
    assert set(report_dir.iterdir()) == set(originals)


@pytest.mark.parametrize("failed_write", [2, 3])
def test_staging_failure_does_not_publish_any_new_content(
    core: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_write: int
) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    paths = [report_dir / f"critical.{suffix}" for suffix in ("json", "md", "html")]
    originals = {path: f"original {path.suffix}".encode() for path in paths}
    for path, content in originals.items():
        path.write_bytes(content)
    write_text = Path.write_text
    writes = 0

    def fail_later_stage(path: Path, *args, **kwargs) -> int:
        nonlocal writes
        if path.is_relative_to(report_dir):
            writes += 1
            if writes == failed_write:
                raise OSError("staging disk is full")
        return write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_later_stage)
    assert critical_misses.main(["--json-out", str(paths[0]), *WINDOW]) == 2
    assert writes == failed_write
    assert {path: path.read_bytes() for path in paths} == originals
    assert set(report_dir.iterdir()) == set(paths)


@pytest.mark.parametrize("failure_kind", ["io-error", "cancelled", "cancelled-again"])
def test_failed_rollback_retains_and_identifies_recoverable_originals(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    failure_kind: str,
) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    paths = [report_dir / f"critical.{suffix}" for suffix in ("json", "md", "html")]
    originals = {path: f"original {path.suffix}".encode() for path in paths}
    for path, content in originals.items():
        path.write_bytes(content)
    replace = Path.replace
    failed = False
    publication_failure = (
        KeyboardInterrupt("publication cancelled")
        if failure_kind == "cancelled"
        else PermissionError("Markdown publication refused")
    )
    recovery_failure = (
        KeyboardInterrupt("recovery cancelled")
        if failure_kind == "cancelled-again"
        else PermissionError("JSON rollback refused")
    )

    def fail_publication_and_json_recovery(source: Path, target: str | Path) -> Path:
        nonlocal failed
        if Path(target) == paths[1] and not failed:
            failed = True
            raise publication_failure
        if Path(target) == paths[0] and failed:
            raise recovery_failure
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_publication_and_json_recovery)
    if failure_kind == "io-error":
        assert critical_misses.main(["--json-out", str(paths[0]), *WINDOW]) == 2
    else:
        with pytest.raises(KeyboardInterrupt) as raised:
            critical_misses.main(["--json-out", str(paths[0]), *WINDOW])
        assert raised.value is (
            publication_failure if failure_kind == "cancelled" else recovery_failure
        )
    for path in paths[1:]:
        assert path.read_bytes() == originals[path]
    recoverable = [
        path
        for path in report_dir.rglob("*")
        if path.is_file() and path.read_bytes() == originals[paths[0]]
    ]
    assert len(recoverable) == 1
    assert str(recoverable[0].parent) in capsys.readouterr().err


def test_successful_replacement_preserves_symlink_targets_and_private_permissions(
    core: Context, tmp_path: Path
) -> None:
    target = tmp_path / "saved.json"
    target.write_bytes(b"previous JSON")
    target.chmod(0o600)
    destination = tmp_path / "critical.json"
    destination.symlink_to(target)
    for suffix in ("md", "html"):
        destination.with_suffix(f".{suffix}").write_bytes(b"previous human report")
    assert critical_misses.main(["--json-out", str(destination), *WINDOW]) == 0
    assert destination.is_symlink() and destination.resolve() == target
    assert json.loads(target.read_bytes()) == []
    assert target.stat().st_mode & 0o777 == 0o600
    for suffix in ("md", "html"):
        assert destination.with_suffix(f".{suffix}").read_bytes() != b"previous human report"


@pytest.mark.parametrize("cleanup_index", [1, 2, 3])
@pytest.mark.parametrize("outcome", ["success", "io-error", "cancelled"])
def test_cleanup_failure_preserves_the_publication_outcome(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    cleanup_index: int,
    outcome: str,
) -> None:
    seed_misses(core)
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    paths = [report_dir / f"critical.{suffix}" for suffix in ("json", "md", "html")]
    originals = {path: f"original {path.suffix}".encode() for path in paths}
    for path, content in originals.items():
        path.write_bytes(content)
    remove_tree = critical_misses.shutil.rmtree
    cleanup_attempts = 0
    retained = None

    def fail_one_cleanup(path: str | Path, *args, **kwargs) -> None:
        nonlocal cleanup_attempts, retained
        if Path(path).is_relative_to(report_dir):
            cleanup_attempts += 1
            if cleanup_attempts == cleanup_index:
                retained = Path(path)
                raise PermissionError("staging cleanup refused")
        remove_tree(path, *args, **kwargs)

    monkeypatch.setattr(critical_misses.shutil, "rmtree", fail_one_cleanup)
    publication_error = (
        KeyboardInterrupt("publication cancelled")
        if outcome == "cancelled"
        else OSError("report replacement refused")
    )
    if outcome != "success":
        replace = Path.replace
        failed = False

        def fail_publication(source: Path, target: str | Path) -> Path:
            nonlocal failed
            if Path(target) == paths[1] and not failed:
                failed = True
                raise publication_error
            return replace(source, target)

        monkeypatch.setattr(Path, "replace", fail_publication)
    if outcome == "cancelled":
        with pytest.raises(KeyboardInterrupt) as raised:
            critical_misses.main(["--json-out", str(paths[0]), *WINDOW])
        assert raised.value is publication_error
    else:
        assert critical_misses.main(["--json-out", str(paths[0]), *WINDOW]) == (
            0 if outcome == "success" else 2
        )
    captured = capsys.readouterr()
    if outcome == "success":
        assert json.loads(captured.out)["recorded_misses"] == 2
        rows = json.loads(paths[0].read_bytes())
        assert [row["title"] for row in rows] == [HOSTILE, "Already reported area"]
        for path in paths[1:]:
            assert all(row["finding_id"] in path.read_text() for row in rows)
    else:
        assert {path: path.read_bytes() for path in paths} == originals
        if outcome == "io-error":
            assert str(publication_error) in captured.err
    assert retained is not None
    assert str(retained) in captured.err
    assert {path for path in report_dir.iterdir() if path.is_dir()} == {retained}


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    ("phase", "existing"),
    [
        ("after-backup", True),
        ("before-install", True),
        ("after-install", True),
        ("after-install", False),
    ],
)
def test_cancellation_restores_reports_and_propagates_the_original_signal(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancellation_type: type[BaseException],
    phase: str,
    existing: bool,
) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    paths = [report_dir / f"critical.{suffix}" for suffix in ("json", "md", "html")]
    originals = {path: f"original {path.suffix}".encode() for path in paths}
    if existing:
        for path, content in originals.items():
            path.write_bytes(content)
    replace = Path.replace
    cancellation = cancellation_type("publication cancelled")
    interrupted = False

    def cancel_publication(source: Path, target: str | Path) -> Path:
        nonlocal interrupted
        if not interrupted:
            if phase == "after-backup" and source == paths[1]:
                replace(source, target)
                interrupted = True
                raise cancellation
            if phase != "after-backup" and Path(target) == paths[1]:
                if phase == "after-install":
                    replace(source, target)
                interrupted = True
                raise cancellation
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", cancel_publication)
    with pytest.raises(cancellation_type) as raised:
        critical_misses.main(["--json-out", str(paths[0]), *WINDOW])
    assert raised.value is cancellation
    if existing:
        assert {path: path.read_bytes() for path in paths} == originals
    else:
        assert all(not path.exists() for path in paths)
    assert set(report_dir.iterdir()) == (set(paths) if existing else set())
