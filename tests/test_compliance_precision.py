from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from traust_core.v1.context import ArtifactsConfig, Config, Context, DatabaseConfig
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import ComplianceAssessmentArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.detection_quality import COMPLIANCE_PRECISION_GATE
from traust_core.v1.models.insight import CompliancePrecision, ViewFilter, ViewName
from traust_core.v1.models.integrity import sha256_hex
from traust_core.v1.models.inventory import Product, Repository, RepositoryRef
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import AssessmentLog, PublishSpec, PublishSpecs

from tests.test_products_doors import _postgres
from traust.cli import compliance_precision, dashboard_view
from traust.cli.__main__ import main

NOW = datetime(2026, 10, 20, tzinfo=UTC)
NIST = ComplianceFramework("nist-800-53-rev5")
PCI = ComplianceFramework("pci-dss-v4")
HOSTILE = "tls | `tick` <img src=x onerror=alert(1)> [docs](javascript:alert(1))\n## forged"
TRAVERSAL = "../../outside"
FILENAMES = {f"compliance-precision.{suffix}" for suffix in ("json", "md", "html")}


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
        monkeypatch.setattr(compliance_precision, "load", lambda _: context)
        monkeypatch.setattr(dashboard_view, "load", lambda _, **kwargs: context)
        try:
            yield context
        finally:
            context.database.dispose()


def result(
    check_id: str,
    verdict: str = "not_satisfied",
    *,
    source: str = "check",
    framework: ComplianceFramework = NIST,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "framework": framework.value,
        "control_id": f"ctl-{check_id}",
        "classification": "evidence_review" if source == "agent" else "deterministic",
        "verdict": verdict,
        "verdict_source": source,
        "check_id": check_id,
        "evidence": [{"sha256": "0" * 64, "kind": "iac_file", "locator": "main.tf:1"}],
        **(
            {"reason": "no measured evidence"}
            if verdict in ("not_assessed", "not_applicable")
            else {}
        ),
        **extra,
    }


def override(
    check_id: str,
    *,
    original: str | None = "not_satisfied",
    verdict: str = "satisfied",
    framework: ComplianceFramework = NIST,
) -> dict[str, Any]:
    attribution = {
        "by": "alice",
        "date": "2026-10-05",
        "rationale": "reviewed compensating control",
    }
    if original is not None:
        attribution["overridden_check_verdict"] = original
    return result(
        check_id, verdict, source="human_override", framework=framework, override=attribution
    )


def document(
    *results: dict[str, Any], frameworks: tuple[ComplianceFramework, ...] = (NIST,)
) -> ComplianceAssessmentArtifact:
    coverage = {}
    for framework in frameworks:
        counts = dict.fromkeys(
            (
                "total_in_scope",
                "deterministic",
                "evidence_review",
                "organizational",
                "satisfied",
                "not_satisfied",
                "not_applicable",
                "not_assessed",
            ),
            0,
        )
        for row in results:
            if row["framework"] == framework.value:
                counts["total_in_scope"] += 1
                counts[row["classification"]] += 1
                counts[row["verdict"]] += 1
        coverage[framework.value] = counts
    return ComplianceAssessmentArtifact.from_document(
        {
            "metadata": {
                "artifact": "compliance-assessment",
                "harness_version": "h-1",
                "target": {"kind": "environment"},
                "frameworks": [{"id": framework.value} for framework in frameworks],
                "registry_hash": "0" * 64,
                "generated_at": "2026-10-05T00:00:00Z",
            },
            "coverage": coverage,
            "results": list(results),
        }
    )


def record(
    core: Context,
    doc: ComplianceAssessmentArtifact,
    *,
    copies: int = 1,
    kind: AssessmentKind = AssessmentKind.COMPLIANCE,
) -> None:
    """Use the producer's artifact publisher and assessment log, including per-ref attachment."""
    publisher = core.artifact_publisher(PublishSpecs(PublishSpec(ComplianceAssessmentArtifact)))
    published = publisher.publish_artifact(doc)
    uow = SqlTraustUnitOfWork(core.database)
    with uow:
        repository = uow.repositories.add(
            Repository(url=f"https://github.com/example/{uuid4().hex}", public=True)
        )
        refs = [
            uow.repository_refs.add(
                RepositoryRef(
                    repository_id=repository.id,
                    sha=f"{index + 1:040x}",
                    name=f"branch-{index}",
                    kind="branch",
                )
            )
            for index in range(copies)
        ]
        uow.commit()
    for ref in refs:
        AssessmentLog(uow).add(
            Assessment(
                repository_ref_id=ref.id,
                kind=kind,
                status="completed",
                assessor="tool:fixture",
                assessor_version="h-1",
                occurred_at=NOW,
            ),
            published.artifact_id,
            sha256_hex(doc.payload),
        )


def seed_population(core: Context) -> None:
    record(
        core,
        document(
            result("tls"),
            override("tls"),
            result("mfa"),
            result("mfa", "satisfied"),
            override("dismissed"),
            result(HOSTILE),
            override(HOSTILE),
            result(TRAVERSAL),
            result("agent-only", source="agent"),
            result("unknown", "not_assessed"),
            result("inapplicable", "not_applicable"),
            override("unattributed-original", original=None),
            override("unknown-original", original="unknown"),
            override("already-satisfied", original="satisfied"),
            result(""),
            result("pci-only", framework=PCI),
            frameworks=(NIST, PCI),
        ),
        copies=2,
    )
    # A matching result in a document declaring another framework is not a NIST population.
    record(core, document(result("wrong-document"), frameworks=(PCI,)))
    record(core, document(result("mfa")))
    record(core, document(result("wrong-kind")), kind=AssessmentKind.SCANNER)
    # An imported document without a compliance assessment is not a recorded compliance run.
    core.artifact_publisher(
        PublishSpecs(PublishSpec(ComplianceAssessmentArtifact))
    ).publish_artifact(document(result("unattached")))


def invoke(entry: Callable[[list[str]], int], argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = entry(argv)
        except SystemExit as exc:
            assert isinstance(exc.code, int)
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def sweep(out: Path, *flags: str) -> list[str]:
    return ["--framework", NIST.value, "--out-dir", str(out), *flags]


def dashboard(out: Path, *flags: str) -> list[str]:
    return ["compliance-precision", "--framework", NIST.value, "--out", str(out), *flags]


def report_paths(out: Path) -> list[Path]:
    return [out / f"compliance-precision.{suffix}" for suffix in ("json", "md", "html")]


def store_snapshot(core: Context) -> tuple[dict[str, list[str]], dict[Path, tuple[bytes, int]]]:
    metadata = sa.MetaData()
    metadata.reflect(bind=core.database)
    with core.database.connect() as conn:
        rows = {
            name: sorted(repr(tuple(row)) for row in conn.execute(sa.select(table)))
            for name, table in metadata.tables.items()
        }
    root = core.config.artifacts_path()
    objects = {
        path.relative_to(root): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }
    return rows, objects


def test_grouped_sweep_exports_native_population_as_three_fixed_reports_and_legacy_stdout(
    core: Context, tmp_path: Path
) -> None:
    seed_population(core)
    before = store_snapshot(core)
    out = tmp_path / "reports"
    code, stdout, stderr = invoke(main, ["sweep", "compliance-precision", *sweep(out)])
    assert code == 0, stderr
    assert {path.name for path in out.iterdir()} == FILENAMES
    flat = json.loads((out / "compliance-precision.json").read_bytes())
    assert set(flat) == {"framework", "assessments", "checks", "gate"}
    assert (flat["framework"], flat["assessments"], flat["gate"]) == (
        NIST.value,
        2,
        COMPLIANCE_PRECISION_GATE,
    )
    checks = {row["check_id"]: row for row in flat["checks"]}
    assert set(checks) == {"tls", "mfa", "dismissed", HOSTILE, TRAVERSAL}
    assert [(checks[name]["fired"], checks[name]["dismissed"]) for name in ("tls", "mfa")] == [
        (2, 1),
        (2, 0),
    ]
    assert (checks["tls"]["precision"], checks["tls"]["flagged"]) == (0.5, True)
    assert (checks["mfa"]["precision"], checks["mfa"]["flagged"]) == (1.0, False)
    assert (checks["dismissed"]["precision"], checks["dismissed"]["flagged"]) == (0.0, True)
    assert all(row["gate"] == COMPLIANCE_PRECISION_GATE for row in checks.values())
    answer = json.loads(stdout)
    assert answer == {
        **flat,
        "flagged_checks": [row["check_id"] for row in flat["checks"] if row["flagged"]],
    }
    rendered = core.services().insight.publish(
        ViewName.COMPLIANCE_PRECISION, ViewFilter(framework=NIST)
    )
    assert isinstance(rendered.model, CompliancePrecision)
    assert flat == rendered.model.calibration.model_dump(mode="json")
    markdown, html = (path.read_text() for path in report_paths(out)[1:])
    assert (markdown, html) == (rendered.markdown, rendered.html)
    for text in (markdown, html):
        assert "<img" not in text
        assert "\n## forged" not in text
        assert "tls" in text and "mfa" in text
    assert "[docs](javascript:" not in markdown
    assert not (tmp_path / "outside").exists()
    assert store_snapshot(core) == before


@pytest.mark.parametrize("framework", [NIST, PCI])
@pytest.mark.parametrize("gate", [None, 0.0, 0.49, 0.5, 1.0])
def test_dashboard_exports_canonical_wrapper_and_matches_sweep_at_every_gate(
    core: Context, tmp_path: Path, framework: ComplianceFramework, gate: float | None
) -> None:
    seed_population(core)
    before = store_snapshot(core)
    out = tmp_path / "dashboard"
    flags = [] if gate is None else ["--precision-gate", str(gate)]
    code, stdout, stderr = invoke(
        main,
        [
            "dashboard",
            "view",
            "compliance-precision",
            "--framework",
            framework.value,
            "--out",
            str(out),
            *flags,
        ],
    )
    assert code == 0, stderr
    answer = json.loads(stdout)
    paths = {path.suffix: path for path in map(Path, answer["written"])}
    assert set(paths) == {".json", ".md", ".html"}
    assert set(out.iterdir()) == set(paths.values())
    wrapper = json.loads(paths[".json"].read_bytes())
    assert set(wrapper) == {"calibration"}
    flat = wrapper["calibration"]
    selected_gate = COMPLIANCE_PRECISION_GATE if gate is None else gate
    assert (flat["framework"], flat["assessments"], flat["gate"]) == (
        framework.value,
        2,
        selected_gate,
    )
    checks = {row["check_id"]: row for row in flat["checks"]}
    if framework == PCI:
        assert set(checks) == {"pci-only"}
    else:
        assert set(checks) == {"tls", "mfa", "dismissed", HOSTILE, TRAVERSAL}
        assert checks[HOSTILE]["precision"] == 0.5
    for row in checks.values():
        assert row["gate"] == selected_gate
        assert row["flagged"] is (row["precision"] <= selected_gate)
    assert answer["model"] == wrapper
    assert all(path.parent == out for path in paths.values())
    legacy_out = tmp_path / "sweep"
    sweep_flags = [] if gate is None else ["--gate", str(gate)]
    code, stdout, stderr = invoke(
        compliance_precision.main,
        ["--framework", framework.value, "--out-dir", str(legacy_out), *sweep_flags],
    )
    assert code == 0, stderr
    assert json.loads(report_paths(legacy_out)[0].read_bytes()) == flat
    assert json.loads(stdout) == {
        **flat,
        "flagged_checks": [row["check_id"] for row in flat["checks"] if row["flagged"]],
    }
    assert [paths[suffix].read_bytes() for suffix in (".md", ".html")] == [
        path.read_bytes() for path in report_paths(legacy_out)[1:]
    ]
    assert store_snapshot(core) == before


@pytest.mark.parametrize("population", ["empty", "unknown-only", "zero-firings"])
def test_unmeasured_populations_do_not_become_perfect_precision_or_coverage(
    core: Context, tmp_path: Path, population: str
) -> None:
    if population == "unknown-only":
        record(
            core,
            document(
                result("unknown", "not_assessed"),
                result("inapplicable", "not_applicable"),
                override("unknown-original", original="unknown"),
                override("missing-original", original=None),
            ),
        )
    elif population == "zero-firings":
        record(core, document(result("passed", "satisfied"), result("agent", source="agent")))
    before = store_snapshot(core)
    for entry, argv in (
        (compliance_precision.main, sweep(tmp_path / "sweep")),
        (dashboard_view.main, dashboard(tmp_path / "dashboard")),
    ):
        code, stdout, stderr = invoke(entry, argv)
        assert code == 0, stderr
        answer = json.loads(stdout)
        flat = answer["model"]["calibration"] if "model" in answer else answer
        assert flat["assessments"] == (0 if population == "empty" else 1)
        assert flat["checks"] == []
        assert "precision" not in flat and "coverage" not in flat
        if "flagged_checks" in answer:
            assert answer["flagged_checks"] == []
        out = Path(argv[argv.index("--out" if "--out" in argv else "--out-dir") + 1])
        paths = (
            [Path(path) for path in answer["written"]] if "written" in answer else report_paths(out)
        )
        assert set(out.iterdir()) == set(paths)
        assert {path.suffix for path in paths} == {".json", ".md", ".html"}
        for path in paths:
            if path.suffix == ".json":
                continue
            text = path.read_text().lower()
            assert "unmeasured" in text
            assert "100%" not in text
    assert store_snapshot(core) == before


@pytest.mark.parametrize("gate", ["-0.1", "1.1", "nan", "inf", "-inf", "not-a-number"])
@pytest.mark.parametrize("command", ["sweep", "dashboard"])
def test_invalid_gates_refuse_without_creating_exports(
    core: Context, tmp_path: Path, gate: str, command: str
) -> None:
    out = tmp_path / "refused"
    entry, argv = (
        (compliance_precision.main, sweep(out, f"--gate={gate}"))
        if command == "sweep"
        else (dashboard_view.main, dashboard(out, f"--precision-gate={gate}"))
    )
    code, stdout, stderr = invoke(entry, argv)
    assert code == 2 and not stdout and stderr
    assert not out.exists()


@pytest.mark.parametrize("framework", [None, "nist-800-53-r5", "", "unknown"])
@pytest.mark.parametrize("command", ["sweep", "dashboard"])
def test_missing_or_invalid_framework_refuses_without_exports(
    core: Context, tmp_path: Path, framework: str | None, command: str
) -> None:
    out = tmp_path / "refused"
    flags = [] if framework is None else ["--framework", framework]
    entry, argv = (
        (compliance_precision.main, ["--out-dir", str(out), *flags])
        if command == "sweep"
        else (dashboard_view.main, ["compliance-precision", "--out", str(out), *flags])
    )
    code, stdout, stderr = invoke(entry, argv)
    assert code == 2 and not stdout and stderr
    assert not out.exists()


@pytest.mark.parametrize(
    "flags",
    [
        ["--framework", NIST.value],
        ["--precision-gate", "0.5"],
        ["--framework", NIST.value, "--precision-gate", "0.5"],
    ],
)
def test_other_views_refuse_compliance_only_flags(
    core: Context, tmp_path: Path, flags: list[str]
) -> None:
    out = tmp_path / "refused"
    code, stdout, stderr = invoke(
        dashboard_view.main, ["findings-trend", "--out", str(out), *flags]
    )
    assert code == 2 and not stdout and stderr
    assert not out.exists()


@pytest.mark.parametrize(
    "flags",
    [
        ["--product", "widget"],
        ["--team-id", str(UUID(int=1))],
        ["--category", "authorization"],
        ["--as-of", NOW.isoformat()],
        ["--since", "2026-10-01T00:00:00Z"],
        ["--until", NOW.isoformat()],
        ["--since", "2026-10-01T00:00:00Z", "--until", NOW.isoformat()],
        ["--bucket", "week"],
        ["--compare-as-of", NOW.isoformat()],
        ["--artifact-id", str(UUID(int=1))],
        ["--assessment-id", str(UUID(int=1))],
        ["--report-stem", "image-container-audit"],
        ["--panel", "attack"],
        ["--first-party-divisor", "2"],
        ["--sla-policy", "not-read.yaml"],
        ["--invoice", "not-read.csv"],
    ],
)
def test_compliance_view_refuses_unsupported_scope_without_exports(
    core: Context, tmp_path: Path, flags: list[str]
) -> None:
    with SqlTraustUnitOfWork(core.database) as uow:
        uow.products.add(Product(slug="widget", name="Widget"))
        uow.commit()
    before = store_snapshot(core)
    out = tmp_path / "refused"
    code, stdout, stderr = invoke(dashboard_view.main, dashboard(out, *flags))
    assert code == 2 and not stdout and stderr
    assert "not registered" not in stderr
    assert "No such file" not in stderr
    assert not out.exists()
    assert store_snapshot(core) == before


def test_native_repository_scope_is_refused_instead_of_silently_ignored(core: Context) -> None:
    with pytest.raises(ValidationError):
        core.services().insight.publish(
            ViewName.COMPLIANCE_PRECISION,
            ViewFilter(framework=NIST, repository_id=UUID(int=1)),
        )


@pytest.mark.parametrize("destination", ["file", "parent-file"])
def test_invalid_output_directory_does_not_change_existing_data(
    core: Context, tmp_path: Path, destination: str
) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"original evidence")
    before = store_snapshot(core)
    entries = set(tmp_path.iterdir())
    out = blocked if destination == "file" else blocked / "reports"
    code, stdout, stderr = invoke(compliance_precision.main, sweep(out))
    assert code == 2 and not stdout and stderr
    assert blocked.read_bytes() == b"original evidence"
    assert set(tmp_path.iterdir()) == entries
    assert store_snapshot(core) == before


@pytest.mark.parametrize("blocked", [0, 1, 2])
@pytest.mark.parametrize("existing", [False, True])
def test_nonregular_report_destination_preserves_the_whole_set(
    core: Context, tmp_path: Path, blocked: int, existing: bool
) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    paths = report_paths(out)
    originals = {}
    for index, path in enumerate(paths):
        if index == blocked:
            path.mkdir()
        elif existing:
            originals[path] = f"original {path.suffix}".encode()
            path.write_bytes(originals[path])
    code, stdout, stderr = invoke(compliance_precision.main, sweep(out))
    assert code == 2 and not stdout and stderr
    assert paths[blocked].is_dir() and not list(paths[blocked].iterdir())
    assert {path: path.read_bytes() for path in originals} == originals
    assert set(out.iterdir()) == {paths[blocked], *originals}


@pytest.mark.parametrize("pair", [(0, 1), (0, 2), (1, 2)])
@pytest.mark.parametrize("alias", ["symlink", "relative-symlink", "hardlink"])
def test_fixed_name_aliases_and_hardlinks_refuse_without_overwriting_reports(
    core: Context, tmp_path: Path, pair: tuple[int, int], alias: str
) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    paths = report_paths(out)
    for path in paths:
        path.write_bytes(f"original {path.suffix}".encode())
    source, target = (paths[index] for index in pair)
    target.unlink()
    if alias == "hardlink":
        target.hardlink_to(source)
    else:
        target.symlink_to(source.name if alias == "relative-symlink" else source)
    originals = {path: path.read_bytes() for path in paths}
    identities = {path: (path.lstat().st_ino, path.is_symlink()) for path in paths}
    code, stdout, stderr = invoke(compliance_precision.main, sweep(out))
    assert code == 2 and not stdout and stderr
    assert {path: path.read_bytes() for path in paths} == originals
    assert {path: (path.lstat().st_ino, path.is_symlink()) for path in paths} == identities
    assert set(out.iterdir()) == set(paths)


@pytest.mark.parametrize("failed_write", [1, 2, 3])
@pytest.mark.parametrize("existing", [False, True])
def test_staging_failure_preserves_all_existing_reports_and_removes_staging(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_write: int,
    existing: bool,
) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    paths = report_paths(out)
    originals = {path: f"original {path.suffix}".encode() for path in paths} if existing else {}
    for path, content in originals.items():
        path.write_bytes(content)
    write_text = Path.write_text
    stages = []

    def fail_stage(path: Path, *args: Any, **kwargs: Any) -> int:
        if path.parent.parent == out:
            stages.append(path.parent)
            assert path.parent.name.startswith(".traust-report-")
            if len(stages) == failed_write:
                raise OSError("staging disk is full")
        return write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_stage)
    code, stdout, stderr = invoke(compliance_precision.main, sweep(out))
    assert code == 2 and not stdout and "staging disk is full" in stderr
    assert len(stages) == failed_write
    assert {path: path.read_bytes() for path in originals} == originals
    assert set(out.iterdir()) == set(originals)


@pytest.mark.parametrize("blocked", [0, 1, 2])
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("after_install", [False, True])
def test_replacement_failure_restores_the_complete_report_set(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked: int,
    existing: bool,
    after_install: bool,
) -> None:
    out = tmp_path / "reports"
    out.mkdir()
    paths = report_paths(out)
    originals = {path: f"original {path.suffix}".encode() for path in paths} if existing else {}
    for path, content in originals.items():
        path.write_bytes(content)
    replace = Path.replace
    failed = False

    def fail_replacement(source: Path, target: str | Path) -> Path:
        nonlocal failed
        if Path(target) == paths[blocked] and not failed:
            failed = True
            if after_install:
                replace(source, target)
            raise PermissionError("report replacement refused")
        return replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_replacement)
    code, stdout, stderr = invoke(compliance_precision.main, sweep(out))
    assert code == 2 and not stdout and "report replacement refused" in stderr
    assert failed
    assert {path: path.read_bytes() for path in originals} == originals
    assert set(out.iterdir()) == set(originals)


def test_replacement_keeps_symlink_targets_and_existing_private_permissions(
    core: Context, tmp_path: Path
) -> None:
    record(core, document(result("tls"), override("tls")))
    out = tmp_path / "reports"
    out.mkdir()
    paths = report_paths(out)
    target = tmp_path / "saved.json"
    target.write_bytes(b"previous JSON")
    target.chmod(0o600)
    paths[0].symlink_to(target)
    for path in paths[1:]:
        path.write_bytes(b"previous report")
        path.chmod(0o600)
    code, stdout, stderr = invoke(compliance_precision.main, sweep(out))
    assert code == 0, stderr
    assert paths[0].is_symlink() and paths[0].resolve() == target
    assert json.loads(target.read_bytes())["checks"][0]["precision"] == 0.5
    assert json.loads(stdout)["flagged_checks"] == ["tls"]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in paths)
    assert all(path.read_bytes() != b"previous report" for path in paths[1:])
    assert {path.name for path in out.iterdir()} == FILENAMES
