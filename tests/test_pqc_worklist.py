"""PQC worklist publication over real SQLite/Postgres stores, without invoking scanning."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from traust_core.v1.context import ArtifactsConfig, Config, Context, DatabaseConfig
from traust_core.v1.models.common import Provenance, ToolRequest
from traust_core.v1.models.findings import CandidateFormat
from traust_core.v1.models.insight import ViewFilter, ViewName
from traust_core.v1.models.inventory import Component, Product, Release, Repository, RepositoryRef
from traust_core.v1.models.pqc import PqcFilter
from traust_core.v1.models.vocabulary import SourceType
from traust_core.v1.providers.clock import FixedClock
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from tests.test_pqc_sweep import Scanner
from tests.test_products_doors import _postgres
from traust.cli import dashboard_view, pqc

NOW = datetime(2026, 10, 24, tzinfo=UTC)
HOSTILE = (
    'raw | `tick` <img src=x onerror="alert(1)"> '
    "[x](javascript:alert(1))\n## forged </script><script>window.__pqcInjected=1</script>"
)


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
        monkeypatch.setattr(pqc, "load", lambda _: context)
        monkeypatch.setattr(dashboard_view, "load", lambda *_, **__: context)
        yield context
        context.database.dispose()


def repository(
    core: Context, url: str, *, commit: bool = True
) -> tuple[Repository, RepositoryRef | None]:
    with SqlTraustUnitOfWork(core.database) as uow:
        repo = uow.repositories.add(Repository(url=url, public=True))
        ref = (
            uow.repository_refs.add(
                RepositoryRef(
                    repository_id=repo.id,
                    sha="a" * 40,
                    name="main",
                    kind="branch",
                )
            )
            if commit
            else None
        )
        uow.commit()
    return repo, ref


def test_legacy_stdout_keeps_null_state_and_creates_no_default_files(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registered, ref = repository(core, "https://github.com/example/registered")
    waiting, _ = repository(core, "https://github.com/example/waiting", commit=False)
    out = tmp_path / "working"
    out.mkdir()
    monkeypatch.chdir(out)
    assert pqc.worklist([]) == 0
    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert isinstance(rows, list) and len(rows) == 2
    by_id = {row["repository_id"]: row for row in rows}
    assert by_id[str(registered.id)]["repository_ref_id"] == str(ref.id)
    assert by_id[str(registered.id)]["scan"] == {
        "repository_ref_id": str(ref.id),
        "assessment_id": None,
        "basis": None,
        "current": None,
    }
    assert by_id[str(registered.id)]["access"]["observed_at"] is None
    assert by_id[str(registered.id)]["access"]["archived"] is None
    assert by_id[str(waiting.id)]["repository_ref_id"] is None
    assert by_id[str(waiting.id)]["sha"] is None
    assert by_id[str(waiting.id)]["scan"] is None
    assert by_id[str(waiting.id)]["reason"] == "no-registered-commit"
    assert by_id[str(waiting.id)]["route"] == "access-request"
    assert captured.err
    assert list(out.iterdir()) == []


def test_native_ref_scope_distinguishes_all_from_empty_and_selects_one_commit_per_repo(
    core: Context,
) -> None:
    repo, first = repository(core, "https://github.com/example/widget")
    waiting, _ = repository(core, "https://github.com/example/waiting", commit=False)
    assert first is not None
    with SqlTraustUnitOfWork(core.database) as uow:
        recent = uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id,
                sha="b" * 40,
                name="newer",
                kind="branch",
            )
        )
        default = uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id,
                sha="c" * 40,
                name="default",
                kind="branch",
                is_default=True,
            )
        )
        tied = uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id,
                sha="d" * 40,
                name="tie",
                kind="branch",
            )
        )
        table = uow.repository_refs.table
        for ref, created_at in (
            (first, NOW),
            (recent, NOW + timedelta(days=1)),
            (default, NOW - timedelta(days=1)),
            (tied, NOW + timedelta(days=1)),
        ):
            uow.connection.execute(
                sa.update(table).where(table.c.id == ref.id).values(created_at=created_at)
            )
        uow.commit()
    insight = core.services().insight
    global_view = insight.publish(ViewName.PQC_WORKLIST, ViewFilter()).model
    assert {entry.repository_id for entry in global_view.entries} == {repo.id, waiting.id}
    assert [
        entry.repository_ref_id for entry in global_view.entries if entry.repository_id == repo.id
    ] == [default.id]
    selected = insight.publish(
        ViewName.PQC_WORKLIST,
        ViewFilter(repository_ref_ids=(first.id, recent.id)),
    ).model
    assert [entry.repository_ref_id for entry in selected.entries] == [recent.id]
    assert selected.repository_ref_ids == (first.id, recent.id)
    tied_view = insight.publish(
        ViewName.PQC_WORKLIST,
        ViewFilter(repository_ref_ids=(recent.id, tied.id)),
    ).model
    assert [entry.repository_ref_id for entry in tied_view.entries] == [
        max((recent.id, tied.id), key=str)
    ]
    assert (
        insight.publish(ViewName.PQC_WORKLIST, ViewFilter(repository_ref_ids=())).model.entries
        == ()
    )
    assert core.services().pqc.worklist(PqcFilter(repository_ref_ids=())) == ()


def test_product_scope_intersects_requested_commits_in_both_public_consumers(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inside, shipped = repository(core, "https://github.com/example/shipped")
    outside, unrelated = repository(core, "https://github.com/example/unrelated")
    with SqlTraustUnitOfWork(core.database) as uow:
        product = uow.products.add(Product(slug="pqc-fixture", name="PQC fixture"))
        other = uow.products.add(Product(slug="other-fixture", name="Other fixture"))
        release = uow.releases.add(Release(product_id=product.id, version="1.0"))
        uow.components.add(Component(release_id=release.id, repository_ref_id=shipped.id))
        uow.commit()
    services = core.services()
    for refs, expected in (
        (None, [shipped.id]),
        ((), []),
        ((shipped.id, unrelated.id), [shipped.id]),
        ((unrelated.id,), []),
    ):
        model = services.insight.publish(
            ViewName.PQC_WORKLIST,
            ViewFilter(product_ids=(product.id,), repository_ref_ids=refs),
        ).model
        assert [entry.repository_ref_id for entry in model.entries] == expected
    assert (
        pqc.worklist(
            [
                "--product",
                "pqc-fixture",
                "--repo",
                inside.url,
                shipped.sha,
                "--repo",
                outside.url,
                unrelated.sha,
            ]
        )
        == 0
    )
    rows = json.loads(capsys.readouterr().out)
    assert [row["repository_ref_id"] for row in rows] == [str(shipped.id)]
    assert (
        dashboard_view.main(
            [
                "pqc-worklist",
                "--product",
                "pqc-fixture",
                "--repository-ref-id",
                str(shipped.id),
                "--repository-ref-id",
                str(unrelated.id),
                "--out",
                str(tmp_path / "scope"),
            ]
        )
        == 0
    )
    answer = json.loads(capsys.readouterr().out)
    assert answer["model"]["product_id"] == str(product.id)
    assert answer["model"]["entries"] == rows
    refused = tmp_path / "multiple-products"
    assert (
        dashboard_view.main(
            [
                "pqc-worklist",
                "--product",
                product.slug,
                "--product",
                other.slug,
                "--out",
                str(refused),
            ]
        )
        == 2
    )
    assert capsys.readouterr().out == ""
    assert not refused.exists()


def test_recorded_scan_with_unknown_currency_remains_nullable_in_legacy_json(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, ref = repository(core, "https://github.com/example/scanned")
    scanner = Scanner()
    core.pqc_scanner = scanner
    source = tmp_path / "source"
    source.mkdir()
    services = core.services()
    services.exposure.ingest_sbom(b'{"bomFormat":"CycloneDX","components":[]}', ref.id)
    recorded = services.pqc.prescan(ref.id, ToolRequest(workspace=source))
    core.pqc_scanner = None
    assert pqc.worklist([]) == 0
    [row] = json.loads(capsys.readouterr().out)
    assert row["scan"]["assessment_id"] == str(recorded.assessment_id)
    assert row["scan"]["basis"] == "source"
    assert row["scan"]["current"] is None
    assert scanner.calls == 1
    assert core.services().pqc.list_readiness(PqcFilter()) == []


def test_chokepoint_fragments_crypto_findings_and_cursor_order_flow_through_cli(
    core: Context, capsys: pytest.CaptureFixture[str]
) -> None:
    crypto, crypto_ref = repository(core, "https://github.com/example/z-crypto")
    tail, _ = repository(core, "https://github.com/example/a-tail")
    high, _ = repository(core, "https://github.com/example/PRIORITY-Z")
    low, _ = repository(core, "https://github.com/example/priority-a")
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fixture",
                        "rules": [
                            {
                                "id": "crypto",
                                "properties": {"tags": ["external/cwe/cwe-327"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "crypto",
                        "message": {"text": "Weak algorithm"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "keys.go"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    core.services().assessment.record_scan(
        crypto_ref.id,
        json.dumps(sarif).encode(),
        CandidateFormat.SARIF,
        Provenance(run_id=uuid4(), source=SourceType.INTERACTIVE, occurred_at=NOW),
    )
    assert pqc.worklist(["--chokepoint", " PRIORITY- "]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [row["repository_id"] for row in rows] == [
        str(high.id),
        str(low.id),
        str(crypto.id),
        str(tail.id),
    ]
    assert [row["priority_tier"] for row in rows] == [
        "chokepoint",
        "chokepoint",
        "crypto-cwe",
        "tail",
    ]
    assert [row["cursor"] for row in rows] == [
        "0|https://github.com/example/PRIORITY-Z",
        "0|https://github.com/example/priority-a",
        "1|https://github.com/example/z-crypto",
        "2|https://github.com/example/a-tail",
    ]


class Elements(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.text: list[str] = []
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, attrs))

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def test_optional_exports_and_dashboard_preserve_raw_data_without_active_hostile_markup(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo, ref = repository(core, HOSTILE)
    markdown = tmp_path / "reports" / "named.native.md"
    assert pqc.worklist(["--chokepoint", "RAW", "--markdown", str(markdown)]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["repository"] == HOSTILE
    assert rows[0]["repository_id"] == str(repo.id)
    assert rows[0]["repository_ref_id"] == str(ref.id)
    assert set(markdown.parent.iterdir()) == {markdown, markdown.with_suffix(".html")}
    assert "<img" not in markdown.read_text()
    assert "\n## forged" not in markdown.read_text()
    assert "[x](javascript:" not in markdown.read_text()
    elements = Elements(markdown.with_suffix(".html").read_text())
    assert not any(tag in {"img", "script"} for tag, _ in elements.tags)
    assert not any(
        name.startswith("on")
        or (name in {"href", "src"} and (value or "").lower().startswith("javascript:"))
        for _, attrs in elements.tags
        for name, value in attrs
    )
    out = tmp_path / "dashboard"
    assert (
        dashboard_view.main(
            [
                "pqc-worklist",
                "--repository-ref-id",
                str(ref.id),
                "--chokepoint",
                "RAW",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    answer = json.loads(capsys.readouterr().out)
    written = [Path(path) for path in answer["written"]]
    assert {path.suffix for path in written} == {".json", ".md", ".html"}
    wrapper = json.loads(next(path for path in written if path.suffix == ".json").read_text())
    assert wrapper == answer["model"]
    assert wrapper["product_id"] is None
    assert wrapper["repository_ref_ids"] == [str(ref.id)]
    assert wrapper["chokepoints"] == ["RAW"]
    assert wrapper["entries"] == rows


@pytest.mark.parametrize("kind", ["same", "symlink", "hardlink", "directory"])
def test_optional_exports_reject_aliased_or_nonregular_destinations_without_partial_output(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    repository(core, "https://github.com/example/widget")
    markdown = tmp_path / "export.md"
    html = markdown.with_suffix(".html")
    if kind == "same":
        markdown = html
        html.write_text("original")
    elif kind == "directory":
        html.mkdir()
    else:
        markdown.write_text("original")
        if kind == "symlink":
            html.symlink_to(markdown)
        else:
            html.hardlink_to(markdown)
    before = {path: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    assert pqc.worklist(["--markdown", str(markdown)]) == 2
    assert capsys.readouterr().out == ""
    assert {path: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()} == before


@pytest.mark.parametrize("existing", [False, True])
def test_optional_publication_failure_restores_the_pair_before_any_stdout(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    existing: bool,
) -> None:
    repository(core, "https://github.com/example/widget")
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    markdown = report_dir / "work.md"
    html = markdown.with_suffix(".html")
    if existing:
        markdown.write_text("previous markdown")
        html.write_text("previous html")
    originals = {path: path.read_bytes() for path in report_dir.iterdir()}
    replace = Path.replace

    def fail_html(path: Path, target: Path) -> Path:
        if path.name == "new" and target == html.resolve():
            raise OSError("publication failure")
        return replace(path, target)

    monkeypatch.setattr(Path, "replace", fail_html)
    assert pqc.worklist(["--markdown", str(markdown)]) == 2
    assert capsys.readouterr().out == ""
    assert {path: path.read_bytes() for path in report_dir.iterdir()} == originals


@pytest.mark.parametrize(
    "options",
    [
        ["--team-id", "00000000-0000-0000-0000-000000000001"],
        ["--category", "crypto"],
        ["--since", NOW.isoformat()],
        ["--until", NOW.isoformat()],
        ["--as-of", NOW.isoformat()],
        ["--bucket", "week"],
        ["--artifact-id", "00000000-0000-0000-0000-000000000001"],
    ],
)
def test_worklist_dashboard_refuses_unsupported_scope_without_files(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str], options: list[str]
) -> None:
    out = tmp_path / "refused"
    assert dashboard_view.main(["pqc-worklist", *options, "--out", str(out)]) == 2
    assert capsys.readouterr().out == ""
    assert not out.exists()


def test_new_worklist_filters_are_not_silently_ignored_by_other_dashboard_views(
    core: Context, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, ref = repository(core, "https://github.com/example/widget")
    for options in (["--repository-ref-id", str(ref.id)], ["--chokepoint", "widget"]):
        out = tmp_path / "refused"
        assert dashboard_view.main(["findings-trend", *options, "--out", str(out)]) == 2
        assert capsys.readouterr().out == ""
        assert not out.exists()


def test_reporting_never_scans_checks_out_ingests_or_writes_store_data(
    core: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository(core, "https://github.com/example/widget")
    services = core.services()

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("reporting invoked a mutating provider/service")

    monkeypatch.setattr(type(services.checkouts), "checkout", forbidden)
    monkeypatch.setattr(type(services.exposure), "ingest_dependencies", forbidden)
    monkeypatch.setattr(type(services.pqc), "prescan", forbidden)
    scanner = Scanner()
    monkeypatch.setattr(scanner, "scan", forbidden)
    core.pqc_scanner = scanner
    before = {
        path: path.read_bytes() for path in core.config.artifacts.path.rglob("*") if path.is_file()
    }

    def no_mutation(conn: object, cursor: object, statement: str, *args: object) -> None:
        assert statement.lstrip().split(None, 1)[0].upper() not in {
            "INSERT",
            "UPDATE",
            "DELETE",
            "REPLACE",
            "CREATE",
            "ALTER",
            "DROP",
        }, statement

    sa.event.listen(core.database, "before_cursor_execute", no_mutation)
    try:
        assert pqc.worklist([]) == 0
        capsys.readouterr()
        assert pqc.worklist(["--markdown", str(tmp_path / "read-only.md")]) == 0
        capsys.readouterr()
        assert dashboard_view.main(["pqc-worklist", "--out", str(tmp_path / "dashboard")]) == 0
        capsys.readouterr()
    finally:
        sa.event.remove(core.database, "before_cursor_execute", no_mutation)
    assert {
        path: path.read_bytes() for path in core.config.artifacts.path.rglob("*") if path.is_file()
    } == before
