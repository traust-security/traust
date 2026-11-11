"""`traust remediation fleet-targets|fleet-record`: the CLI layer only. Arguments become one door
call; the answer is printed as JSON; a typed error is exit 2. The doors are traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.remediation import FleetScope, FleetTarget, golden_failures
from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli import remediation

SPEC = Path(__file__).parents[1] / "harnessing/7-remediate/fleet-fix/specs"
REPO = "https://github.com/example-org/example-service"
REPO_ID, PACKAGE_ID = uuid.uuid4(), uuid.uuid4()
PACKAGES = {(Ecosystem.GO, "golang.org/x/net"): SimpleNamespace(id=PACKAGE_ID)}
TARGET = FleetTarget(
    repository_id=REPO_ID,
    url=REPO,
    product_reach=2,
    evidence="named",
    owner_teams=("team-a", "team-b"),
)


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        fleet_targets=Door([TARGET]),
        record=Door(SimpleNamespace(model_dump=lambda mode: {"fleet_fix_id": "f"})),
        goldens=[],
    )
    remediation_ = SimpleNamespace(fleet_targets=stub.fleet_targets, record=stub.record)
    services = SimpleNamespace(
        remediation=remediation_,
        exposure=SimpleNamespace(find_package=lambda eco, name: PACKAGES.get((eco, name))),
        portfolio=SimpleNamespace(
            find_repository=lambda url: SimpleNamespace(id=REPO_ID) if str(url) == REPO else None,
        ),
    )

    def wired(self: Context) -> SimpleNamespace:
        stub.goldens.append(self.fleet_fix_goldens)
        return services

    monkeypatch.setattr(Context, "services", wired)
    return stub


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    shutil.copytree(Path(__file__).parent / "fixtures" / "config", config)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.mark.parametrize(
    ("argv", "scope"),
    [
        (("--cwe", "CWE-1104"), FleetScope(cwe="CWE-1104")),
        (("--package-id", str(PACKAGE_ID)), FleetScope(package_id=PACKAGE_ID)),
        (
            ("--module", "golang.org/x/net", "--ecosystem", "go"),
            FleetScope(package_id=PACKAGE_ID),
        ),
        (("--repo-url", REPO), FleetScope(repository_ids=(REPO_ID,))),
    ],
)
def test_targets_is_one_door_call_with_the_scope(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], scope: FleetScope
) -> None:
    rc, out = run(remediation.fleet_targets, home, *argv)
    assert (rc, out) == (0, [TARGET.model_dump(mode="json")])
    assert out[0]["owner_teams"] == ["team-a", "team-b"]
    assert doors.fleet_targets.calls == [(scope,)]


def test_targets_without_an_owner_have_none(doors: SimpleNamespace, home: Path) -> None:
    doors.fleet_targets.result = [TARGET.model_copy(update={"owner_teams": ()})]
    rc, out = run(remediation.fleet_targets, home, "--cwe", "CWE-79")
    assert (rc, out[0]["owner_teams"]) == (0, [])


def test_targets_writes_out(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    out = tmp_path / "fleet.json"
    assert run(remediation.fleet_targets, home, "--cwe", "CWE-79", "-o", str(out)) == (0, "")
    assert json.loads(out.read_text())[0]["url"] == REPO


@pytest.mark.parametrize(
    "argv",
    [
        (),
        ("--cwe", "CWE-79", "--repo-url", REPO),
        ("--cwe", "XSS"),
        ("--module", "golang.org/x/net"),
        ("--cwe", "CWE-79", "--ecosystem", "go"),
        ("--module", "golang.org/x/net", "--ecosystem", "cobol"),
    ],
)
def test_targets_needs_exactly_one_valid_scope(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...]
) -> None:
    with pytest.raises(SystemExit):
        run(remediation.fleet_targets, home, *argv)
    assert doors.fleet_targets.calls == []


def test_targets_refusals_are_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = run(remediation.fleet_targets, home, "--repo-url", "https://github.com/x/unknown")
    assert rc == 2 and "not registered" in err
    doors.fleet_targets.result = NotFoundError("package not found")
    rc, err = run(remediation.fleet_targets, home, "--package-id", str(PACKAGE_ID))
    assert rc == 2 and "package not found" in err
    rc, err = run(remediation.fleet_targets, home, "--module", "left-pad", "--ecosystem", "npm")
    assert rc == 2 and "no npm package named left-pad" in err


def test_record_parses_a_yaml_spec(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.fleet_record, home, str(SPEC / "konflux-mutable-pipelineref.yaml"))
    assert (rc, out) == (0, {"fleet_fix_id": "f"})
    [(doc, _)] = doors.record.calls
    assert isinstance(doc, FleetFixArtifact) and doc.id == "konflux-mutable-pipelineref"


def test_record_refusals_are_exit_2(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("matcher: [unclosed")
    assert run(remediation.fleet_record, home, str(bad))[0] == 2
    bad.write_text("id: only-an-id\n")
    assert run(remediation.fleet_record, home, str(bad))[0] == 2
    assert doors.record.calls == []
    doors.record.result = ValidationError("golden test failed")
    rc, err = run(remediation.fleet_record, home, str(SPEC / "tls-verify-enable.yaml"))
    assert rc == 2 and "golden test failed" in err


AST_GREP_SPEC = {
    "id": "go-md5-to-sha256",
    "pattern_ref": "CWE-328 weak hash",
    "description": "md5.New() -> sha256.New()",
    "matcher": {"kind": "ast_grep", "file_glob": ["**/*.go"], "pattern": "md5.New()", "lang": "go"},
    "rewrite": {"template": "sha256.New()"},
    "guards": {"max_files_changed": 5},
    "tests": [
        {
            "name": "swaps md5",
            "file": "pkg/a.go",
            "before": "package pkg\n\nvar h = md5.New()\n",
            "after_contains": ["sha256.New()"],
            "after_not_contains": ["md5.New()"],
        }
    ],
}


def test_record_takes_an_ast_grep_spec_with_the_engine_golden_runner(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    spec = tmp_path / "go-md5-to-sha256.yaml"
    spec.write_text(yaml.safe_dump(AST_GREP_SPEC))
    rc, out = run(remediation.fleet_record, home, str(spec))
    assert (rc, out) == (0, {"fleet_fix_id": "f"})
    [(doc, _)] = doors.record.calls
    [goldens] = doors.goldens
    assert doc.matcher.kind == "ast_grep" and goldens is not None
    if shutil.which("ast-grep"):  # the goldens the door runs, through the runner the CLI wired
        assert (
            golden_failures(doc, "2026-10-25", lambda t: goldens.after(doc, t.file, t.before)) == []
        )
