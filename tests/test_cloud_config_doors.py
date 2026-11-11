"""`traust cloud-config run|check|record` end to end on traust-core, in-process on SQLite and
Postgres; `run` drives traust-engine's real CheckovProvider over a recorded `checkov` on PATH."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import stat
import sys
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
import yaml
from traust_core.v1 import contracts
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import RefName
from traust_core.v1.models.operations import OrderRequest, WorkerId
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import Dialect

from traust.cli import cloud_config
from traust.cli.__main__ import main
from traust.context import load

FIXTURES = Path(__file__).parent / "fixtures" / "cloud_config"
REPORT = json.loads((FIXTURES / "myrepo-cloud-config-audit.json").read_text())
LEGACY_SNAPSHOT = "68045f8c22717898437d7e35ce61990aa0685350b9fd118fab27fecdc85f0dea"
PG_URL = os.environ.get("TRAUST_TEST_DATABASE_URL")
REPO, SHA = "https://github.com/example-org/myrepo", "0123456789abcdef0123456789abcdef01234567"

# Answers `--version` with the pin and a scan with the recorded output, rooted at the scanned dir.
FAKE_CHECKOV = """#!{python}
import sys
from pathlib import Path
argv = sys.argv[1:]
if argv == ["--version"]:
    print("{version}")
    sys.exit(0)
Path("{seen}").write_text(" ".join(argv))
directory = argv[argv.index("--directory") + 1]
sys.stdout.write(Path("{recorded}").read_text().replace("/work/clone-a/myrepo", directory))
"""


@contextlib.contextmanager
def _postgres() -> Iterator[str]:
    """A fresh database on the test server, dropped after: parallel workers never share one."""
    if not PG_URL:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set")
    name = f"traust_cca_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(PG_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.exec_driver_sql(f"CREATE DATABASE {name}")
    url = sa.make_url(PG_URL).set(database=name)
    engine = create_database_engine(url)
    apply_schema(engine, contracts.database_ddl(Dialect.of(engine)))
    engine.dispose()
    try:
        yield url.render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


@pytest.fixture
def sqlite_home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    target = tmp_path / "clones" / "myrepo"
    shutil.copytree(FIXTURES / "source", target)
    return target


def a_checkov(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str = "3.3.6") -> Path:
    """A `checkov` first on PATH; returns where it notes the scan's argv."""
    bin_dir, seen = tmp_path / "bin", tmp_path / "checkov-argv"
    bin_dir.mkdir()
    script = bin_dir / "checkov"
    script.write_text(
        FAKE_CHECKOV.format(
            python=sys.executable,
            version=version,
            seen=seen,
            recorded=FIXTURES / "checkov-3.3.6.json",
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return seen


def run(door: Any, home: Path, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    return rc, out.getvalue(), err.getvalue()


def a_report(tmp_path: Path, doc: dict[str, Any] = REPORT) -> Path:
    path = tmp_path / "myrepo-cloud-config-audit.json"
    path.write_text(json.dumps(doc))
    return path


# run


def test_run_writes_the_legacy_facts_offline_with_secrets_skipped(
    sqlite_home: Path, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = a_checkov(tmp_path, monkeypatch)
    out = tmp_path / "out" / "myrepo-cloud-facts.json"

    rc, stdout, err = run(
        cloud_config.run_, sqlite_home, "--target-dir", str(checkout), "--out", str(out)
    )

    assert rc == 0, err
    facts = json.loads(out.read_text())
    assert (facts["snapshot_id"], len(facts["facts"])) == (LEGACY_SNAPSHOT, 33)
    assert facts["target"] == "myrepo" and facts["checkov_version"] == "3.3.6"
    assert {f["file_path"] for f in facts["facts"]} == {
        "/iac/main.tf",
        "/k8s/deploy.yaml",
        "/img/Dockerfile",
    }
    summary = json.loads(stdout)
    assert summary["wrote"] == str(out) and summary["snapshot_id"] == LEGACY_SNAPSHOT
    assert len(summary["gaps"]) == 2 and all("NOT ASSESSED" in g for g in summary["gaps"])
    argv = seen.read_text().split()
    assert {"--skip-download", "--skip-framework", "secrets"} <= set(argv)
    assert not any("api-key" in a for a in argv)


def test_run_defaults_the_facts_file_to_the_working_directory(
    sqlite_home: Path, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_checkov(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)

    rc, _, err = run(cloud_config.run_, sqlite_home, "--target-dir", str(checkout))

    assert rc == 0, err
    assert json.loads((tmp_path / "myrepo-cloud-facts.json").read_text())["facts"]


def test_run_framework_filter_keeps_only_those_frameworks(
    sqlite_home: Path, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_checkov(tmp_path, monkeypatch)
    out = tmp_path / "facts.json"

    rc, _, err = run(
        cloud_config.run_,
        sqlite_home,
        "--target-dir",
        str(checkout),
        "--framework",
        "terraform, dockerfile",
        "--out",
        str(out),
    )

    assert rc == 0, err
    facts = json.loads(out.read_text())
    assert {f["framework"] for f in facts["facts"]} == {"terraform", "dockerfile"}
    assert len(facts["facts"]) == 14


def test_run_refuses_an_unknown_framework_writing_nothing(
    sqlite_home: Path, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_checkov(tmp_path, monkeypatch)
    out = tmp_path / "facts.json"

    rc, _, err = run(
        cloud_config.run_,
        sqlite_home,
        "--target-dir",
        str(checkout),
        "--framework",
        "terraform,not-a-framework",
        "--out",
        str(out),
    )

    assert rc == 2 and "unknown checkov framework(s): not-a-framework" in err
    assert not out.exists()


def test_run_refuses_a_checkov_other_than_the_pin(
    sqlite_home: Path, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_checkov(tmp_path, monkeypatch, version="3.2.0")
    out = tmp_path / "facts.json"

    rc, _, err = run(
        cloud_config.run_, sqlite_home, "--target-dir", str(checkout), "--out", str(out)
    )

    assert rc == 2 and "version mismatch: pinned 3.3.6" in err
    assert not out.exists()


def test_run_refuses_a_target_that_is_not_a_directory(
    sqlite_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_checkov(tmp_path, monkeypatch)

    rc, _, err = run(cloud_config.run_, sqlite_home, "--target-dir", str(tmp_path / "missing"))

    assert rc == 2 and "not a directory" in err


# check


def test_check_passes_a_cited_report(sqlite_home: Path, tmp_path: Path) -> None:
    rc, out, err = run(cloud_config.check, sqlite_home, str(a_report(tmp_path)))

    assert (rc, out.strip()) == (0, "0 errors"), err


def test_check_fails_each_unexplained_disposition(sqlite_home: Path, tmp_path: Path) -> None:
    doc = copy.deepcopy(REPORT)
    for f in doc["findings"]:
        if f["status"] in ("suppressed", "needs_review"):
            f["rationale"] = ""

    rc, out, _ = run(cloud_config.check, sqlite_home, str(a_report(tmp_path, doc)))

    assert rc == 1
    assert "without rationale" in out and out.strip().endswith("4 errors")


def test_check_refuses_a_report_off_its_schema(sqlite_home: Path, tmp_path: Path) -> None:
    doc = copy.deepcopy(REPORT)
    del doc["findings"][0]["fact_ids"]

    rc, _, err = run(cloud_config.check, sqlite_home, str(a_report(tmp_path, doc)))

    assert rc == 2 and "fact_ids" in err


# record


def test_record_is_a_degraded_assessment_with_a_decision_per_finding(
    home: Path, tmp_path: Path
) -> None:
    report = a_report(tmp_path)

    rc, out, err = run(cloud_config.record, home, str(report), "--repo-url", REPO, "--sha", SHA)

    assert rc == 0, err
    got = json.loads(out)
    assert (got["status"], got["decisions"], got["needs_review"]) == ("degraded", 6, 1)

    rc, again, err = run(cloud_config.record, home, str(report), "--repo-url", REPO, "--sha", SHA)
    assert rc == 0, err
    assert json.loads(again)["assessment_id"] == got["assessment_id"]


def test_record_stamps_the_audit_run_time(home: Path, tmp_path: Path) -> None:
    rc, out, err = run(
        cloud_config.record, home, str(a_report(tmp_path)), "--repo-url", REPO, "--sha", SHA
    )

    assert rc == 0, err
    got = load(home).services().assessment.get(uuid.UUID(json.loads(out)["assessment_id"]))
    assert got.occurred_at == datetime(2026, 10, 20, 9, tzinfo=UTC)


def test_record_without_a_run_time_is_a_new_run_each_time(home: Path, tmp_path: Path) -> None:
    doc = copy.deepcopy(REPORT)
    del doc["metadata"]["generated_at"]
    report = a_report(tmp_path, doc)

    ids = []
    for _ in range(2):
        rc, out, err = run(cloud_config.record, home, str(report), "--repo-url", REPO, "--sha", SHA)
        assert rc == 0, err
        ids.append(json.loads(out)["assessment_id"])

    assert ids[0] != ids[1]


def test_record_refuses_a_run_time_without_a_zone(sqlite_home: Path, tmp_path: Path) -> None:
    doc = copy.deepcopy(REPORT)
    doc["metadata"]["generated_at"] = "2026-10-20T09:00:00"

    rc, _, err = run(
        cloud_config.record,
        sqlite_home,
        str(a_report(tmp_path, doc)),
        "--repo-url",
        REPO,
        "--sha",
        SHA,
    )

    assert rc == 2 and "time zone" in err


def test_record_refuses_a_report_that_fails_its_gate(home: Path, tmp_path: Path) -> None:
    doc = copy.deepcopy(REPORT)
    doc["findings"][4]["rationale"] = ""

    rc, out, err = run(
        cloud_config.record, home, str(a_report(tmp_path, doc)), "--repo-url", REPO, "--sha", SHA
    )

    assert (rc, out) == (2, "") and "fails its gate" in err


def test_the_group_answers_on_the_cli(sqlite_home: Path, tmp_path: Path) -> None:
    out = io.StringIO()
    argv = ["cloud-config", "check", "--config-home", str(sqlite_home), str(a_report(tmp_path))]
    with contextlib.redirect_stdout(out):
        assert main(argv) == 0
    assert out.getvalue().strip() == "0 errors"


def test_record_binds_the_audit_to_its_leased_order(home: Path, tmp_path: Path) -> None:
    services = load(home).services()
    repo = services.portfolio.register_repository(
        HttpsRepoUrl.parse(REPO, load(home).config.forge_hosts), False
    )
    assert repo.id is not None
    services.portfolio.mark_default_branch(repo.id, GitSha.parse(SHA), RefName("main"))
    operator = Principal(
        identity="operator@example.com",
        kind=ActorKind.HUMAN,
        display="operator@example.com",
        verified_by=IdentitySource.LOCAL_USER,
    )
    # Core's submit door asks for an imported default line — the subject a run works
    # on (core#392) — so the audit's repository carries one before the order queues.
    services.portfolio.mark_default_branch(repo.id, GitSha("a" * 40), RefName("main"))
    order = services.ops.submit(
        OrderRequest(asset="cloud_config_audit", priority=1, repository_id=repo.id), operator
    )
    services.ops.claim(WorkerId("machine:runner"), timedelta(minutes=5), order_id=order.id)
    report = str(a_report(tmp_path))

    rc, out, err = run(
        cloud_config.record,
        home,
        report,
        "--repo-url",
        REPO,
        "--sha",
        SHA,
        "--run-id",
        str(order.id),
    )

    assert rc == 0, err
    bound = load(home).services().assessment.list_for_order(order.id)
    assert [str(a.id) for a in bound] == [json.loads(out)["assessment_id"]]
    rc, _, _ = run(
        cloud_config.record,
        home,
        report,
        "--repo-url",
        REPO,
        "--sha",
        SHA,
        "--run-id",
        str(uuid.uuid4()),
    )
    assert rc != 0
