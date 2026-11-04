from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import BelowRangeVerdictsArtifact
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.below_range import (
    BelowRangeInput,
    BelowRangeStatus,
    CoverageGap,
    GapReason,
)
from traust_core.v1.models.dependencies import AdvisoryRecord
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import Repository, RepositoryRef
from traust_core.v1.models.operations import OrderRequest, SessionTask, WorkerId
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs
from traust_core.v1.services.below_range import BelowRangeService

from tests.test_cloud_config_doors import home as home
from tests.test_impact_below_range import PACKET
from tests.test_impact_doors import REPO, SHA, Lookup
from traust.cli import impact, session
from traust.context import load
from traust.ops.sessions import SessionRunner, read_file
from traust.paths import HARNESS_ROOT

WORKER = WorkerId("session-worker")
GAP = CoverageGap(reason=GapReason.SOURCE_UNAVAILABLE, package="unavailable-example")
FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class Estate:
    core: Context
    config: Path
    order_id: UUID
    repo_id: UUID
    ref_id: UUID
    packets_id: UUID


@pytest.fixture
def estate(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Estate:
    shutil.copyfile(FIXTURES / "config/model-registry.yaml", home / "model-registry.yaml")
    core = load(home)

    class Advisory(Lookup):
        def record(self, identifier):
            value = AdvisoryRecord(
                identifier=identifier,
                summary="fixture advisory",
                affected=(PACKET.advisory.affected,),
                declared_severity="HIGH",
                source="https://api.osv.dev/v1/vulns/GHSA-test-0001",
            )
            return Result(value, Acquisition(provider="osv", acquired_at=core.clock.now()))

    core.advisories = Advisory()
    monkeypatch.setattr(impact, "_core", lambda config_home: core)
    with SqlTraustUnitOfWork(core.database) as uow:
        repo = uow.repositories.add(Repository(url=REPO, public=True))
        ref = uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id, name="main", kind="branch", sha=SHA, is_default=True
            )
        )
        uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.REPO_STATE,
                status="completed",
                assessor="fixture",
                assessor_version="1",
                occurred_at=core.clock.now(),
            )
        )
        uow.commit()

    def packets(service, ref_id, workdir, **kwargs):
        return BelowRangeInput(
            repository_ref_id=ref_id,
            installed_exact=2,
            skipped_installs={},
            candidates=1,
            packets=(PACKET,),
            coverage_gaps=(GAP,),
            status=BelowRangeStatus.COMPLETE,
        )

    def fetch(service, data, workdir):
        root = workdir / PACKET.installed_source.root
        root.mkdir(parents=True)
        (root / "lib.go").write_text("package fixture\nfunc Parse() {}\n")

    monkeypatch.setattr(BelowRangeService, "prepare", packets)
    monkeypatch.setattr(BelowRangeService, "fetch", fetch)
    services = core.services()
    scan = services.below_range.scan(repo.id, tmp_path / "packets")
    principal = Principal(identity="operator@example.com", kind=ActorKind.HUMAN, display="Operator")
    queued = services.ops.submit(
        OrderRequest(asset="below_range_review", priority=1, repository_id=repo.id), principal
    )
    claimed = services.ops.claim(WORKER, timedelta(minutes=5))
    assert claimed.id == queued.id
    return Estate(core, home, claimed.id, repo.id, ref.id, scan.assessment_id)


def executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str = "valid") -> Path:
    binary = tmp_path / "bin"
    binary.mkdir(exist_ok=True)
    seen = tmp_path / "executor-seen.json"
    fixture = (FIXTURES / "session/claude-result.json").read_text()
    script = f"""#!{sys.executable}
import json, os, shlex, sys
from pathlib import Path
root = Path(shlex.split(sys.argv[-1])[-1])
task = json.loads((root / "task.json").read_bytes())
index = json.loads((root / "input/below-range.json").read_bytes())
snapshot = {{"root": str(root), "cwd": str(Path.cwd()), "argv": sys.argv, "has_deployment_env": "TRAUST_CONFIG_HOME" in os.environ, "env": dict(os.environ), "task": task, "task_sha256": __import__("hashlib").sha256((root / "task.json").read_bytes()).hexdigest()}}
Path({str(seen)!r}).write_text(json.dumps(snapshot))
doc = {{"artifact": "below-range-verdicts", "packets_assessment_id": index["packets_assessment_id"], "cases": [{{"case": packet["case"], "reviews": [{{"model": task["models"][slot], "verdict": "applicable", "evidence": "lib.go:2 evidence"}} for slot in ("reviewer_a", "reviewer_b")], "verdict": "applicable"}} for packet in index["packets"]], "coverage_gaps": index["coverage_gaps"]}}
output = root / task["output"]["path"]
mode = {mode!r}
if mode == "symlink":
    output.symlink_to({str(tmp_path / "outside.json")!r})
elif mode == "fifo":
    os.mkfifo(output)
elif mode == "parent-symlink":
    output.parent.rmdir()
    output.parent.symlink_to({str(tmp_path / "external-output")!r}, target_is_directory=True)
elif mode != "missing":
    output.write_text("{{}}" if mode == "invalid" else json.dumps(doc))
if mode == "extra":
    (root / "output/ignored.json").write_text("not the declared output")
if mode == "changed-input":
    (root / "input/below-range.json").write_text("changed")
if mode == "changed-input-and-audit":
    index["installed_exact"] += 1
    changed = json.dumps(index).encode()
    (root / "input/below-range.json").write_bytes(changed)
    audit_path = root / ".session-audit.json"
    audit = json.loads(audit_path.read_bytes())
    for entry in audit["inputs"]:
        if entry["path"] == "input/below-range.json":
            entry["bytes"] = len(changed)
            entry["sha256"] = __import__("hashlib").sha256(changed).hexdigest()
    audit_path.write_text(json.dumps(audit))
reply = json.loads({fixture!r})
if mode == "negative-tokens":
    reply["modelUsage"][next(iter(reply["modelUsage"]))]["inputTokens"] = -1
if mode == "empty-session":
    reply["session_id"] = ""
print("not JSON" if mode == "bad-envelope" else json.dumps(reply))
sys.exit(1 if mode == "crash" else 0)
"""
    (binary / "claude").write_text(script)
    (binary / "claude").chmod(0o700)
    (tmp_path / "outside.json").write_text("outside-sentinel")
    (tmp_path / "external-output").mkdir(exist_ok=True)
    (tmp_path / "external-output/verdicts.json").write_text("outside-sentinel")
    monkeypatch.setenv("PATH", f"{binary}{os.pathsep}{os.environ['PATH']}")
    return seen


def run(estate: Estate, *extra: str) -> tuple[int, dict]:
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        code = session.run(
            [
                "--config-home",
                str(estate.config),
                "--skill",
                "dependency-watch",
                "--mode",
                "below-range",
                "--repo",
                REPO,
                "--run-id",
                str(estate.order_id),
                "--worker",
                WORKER,
                *extra,
            ]
        )
    return code, json.loads(printed.getvalue().splitlines()[-1])


def test_a_real_fixture_executor_records_findings_usage_and_audit(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = executor(tmp_path, monkeypatch)
    code, result = run(estate)
    assert code == 0 and result["outcome"] == "succeeded" and result["usage"]
    captured = json.loads(seen.read_text())
    assert Path(captured["cwd"]) == HARNESS_ROOT
    assert not Path(captured["root"]).exists() and not captured["has_deployment_env"]
    # The confinement loads skills (the session's own config dir through the user source)
    # and never the workstation's: --restricted and a blank --setting-sources strip
    # Claude's skills entirely, which is how every artifact-only order died as
    # session-output-invalid before 2026-11-04 (the rig's live run found it).
    argv = captured["argv"]
    assert "--restricted" not in argv and "Bash(*traust.cli*)" in argv
    user_source = argv[argv.index("--setting-sources") + 1]
    assert user_source == "user", argv
    assert captured["env"]["CLAUDE_CONFIG_DIR"].endswith("claude-artifact")
    assert (Path(captured["env"]["CLAUDE_CONFIG_DIR"]) / "skills" / "dependency-watch").exists()
    audit = estate.core.services().ops.manifest(estate.order_id).sessions[0]
    assert audit.task_sha256 == captured["task_sha256"]
    assert tuple(file.path for file in audit.inputs) == tuple(captured["task"]["input"])
    assert all(file.sha256 and file.bytes >= 0 for file in audit.inputs)
    artifact_id = UUID(result["written"][0])
    assert audit.output.artifact_id == artifact_id and audit.output.sha256
    document = estate.core.artifact_publisher(
        PublishSpecs(PublishSpec(BelowRangeVerdictsArtifact))
    ).read(artifact_id, BelowRangeVerdictsArtifact)
    assert document.coverage_gaps[0].package == GAP.package
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        [recorded] = uow.assessments.list_for_run_order(estate.order_id)
        assert len(uow.occurrences.list_for_assessment(recorded.id)) == 1
    again, repeated = run(estate)
    assert again == 0 and repeated["written"] == result["written"]
    assert estate.core.services().ops.manifest(estate.order_id).sessions == (audit,)


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "invalid",
        "symlink",
        "parent-symlink",
        "fifo",
        "changed-input",
        "changed-input-and-audit",
    ],
)
def test_invalid_outputs_record_failure_evidence_without_results(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    seen = executor(tmp_path, monkeypatch, mode)
    code, result = run(estate)
    assert code == 1 and result["reason"] == "session-output-invalid" and result["usage"]
    audit = estate.core.services().ops.manifest(estate.order_id).sessions[0]
    assert audit.output.artifact_id is None
    assert (audit.output.sha256 is not None) == (
        mode in {"invalid", "changed-input", "changed-input-and-audit"}
    )
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        assert uow.assessments.list_for_run_order(estate.order_id) == []
    assert not Path(json.loads(seen.read_text())["root"]).exists()


@pytest.mark.parametrize("mode", ["crash", "bad-envelope", "negative-tokens", "empty-session"])
def test_executor_failures_are_audited(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    executor(tmp_path, monkeypatch, mode)
    code, result = run(estate)
    assert code == 1 and result["reason"] == "runner-crashed"
    audit = estate.core.services().ops.manifest(estate.order_id).sessions[0]
    assert audit.output.artifact_id is None
    assert bool(result["usage"]) == (mode == "crash")
    assert (audit.executor_session is None) == (mode != "crash")
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        assert uow.assessments.list_for_run_order(estate.order_id) == []


def test_extra_output_files_are_ignored(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor(tmp_path, monkeypatch, "extra")
    assert run(estate)[0] == 0


def test_nested_source_names_use_contract_path_order(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fetch(service, data, workdir):
        source = workdir / PACKET.installed_source.root
        (source / "foo").mkdir(parents=True)
        (source / "foo.go").write_text("package fixture\n")
        (source / "foo/bar.go").write_text("package foo\n")

    monkeypatch.setattr(BelowRangeService, "fetch", fetch)
    runner = SessionRunner(
        estate.core.services(),
        estate.core.clock,
        estate.core.model_catalog.resolve_role,
        estate.core.config.forge_hosts,
        "api",
    )
    task = runner.prepare("dependency-watch", "below-range", REPO, tmp_path / "nested")
    paths = tuple(task.input)
    assert paths.index("input/_sources/x/foo.go") < paths.index("input/_sources/x/foo/bar.go")


def test_wrong_workers_and_missing_packets_never_start_an_executor(
    estate: Estate, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args, **kwargs):
        pytest.fail("executor must not start")

    monkeypatch.setattr(session, "execute", unexpected)
    assert run(estate, "--worker", "another-worker")[1]["reason"] == "runner-crashed"
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        ref = uow.repository_refs.add(
            RepositoryRef(
                repository_id=estate.repo_id,
                name="main",
                kind="branch",
                sha="b" * 40,
                is_default=True,
            )
        )
        uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.REPO_STATE,
                status="completed",
                assessor="fixture",
                assessor_version="1",
                occurred_at=estate.core.clock.now() + timedelta(seconds=1),
            )
        )
        uow.commit()
    assert run(estate)[1]["reason"] == "not_found"
    runner = SessionRunner(
        estate.core.services(),
        estate.core.clock,
        estate.core.model_catalog.resolve_role,
        estate.core.config.forge_hosts,
        "air-gapped",
    )
    with pytest.raises(ValueError, match="OSV API"):
        runner.prepare("dependency-watch", "below-range", REPO, estate.config.parent / "refused")


def test_interactive_halves_keep_manual_attribution(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "interactive task"
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert (
            session.prepare(
                [
                    "--config-home",
                    str(estate.config),
                    "--skill",
                    "dependency-watch",
                    "--mode",
                    "below-range",
                    "--repo",
                    REPO,
                    "--task",
                    str(root),
                ]
            )
            == 0
        )
    task = SessionTask.parse(read_file(root, "task.json"))
    assert task.run_id is None
    index = json.loads(read_file(root, "input/below-range.json"))
    models = {slot: getattr(task.models, slot) for slot in ("reviewer_a", "reviewer_b")}
    doc = {
        "artifact": "below-range-verdicts",
        "packets_assessment_id": str(estate.packets_id),
        "cases": [
            {
                "case": PACKET.case,
                "reviews": [
                    {"model": model, "verdict": "applicable", "evidence": "lib.go:2"}
                    for model in models.values()
                ],
                "verdict": "applicable",
            }
        ],
        "coverage_gaps": index["coverage_gaps"],
    }
    (root / task.output.path).write_text(json.dumps(doc))
    with contextlib.redirect_stdout(out):
        assert session.record(["--config-home", str(estate.config), "--task", str(root)]) == 0
    result = json.loads(out.getvalue().splitlines()[-1])
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        reviews = [
            a
            for a in uow.assessments.list_for_ref(estate.ref_id)
            if a.assessor == "skill:dependency-watch"
        ]
    assert len(reviews) == 1 and reviews[0].run_order_id is None
    assert (
        result["outcome"] == "succeeded"
        and estate.core.services().ops.manifest(estate.order_id).sessions == ()
    )


def test_interactive_and_headless_record_the_same_document(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor(tmp_path, monkeypatch)
    code, headless = run(estate)
    assert code == 0
    publisher = estate.core.artifact_publisher(
        PublishSpecs(PublishSpec(BelowRangeVerdictsArtifact))
    )
    document = publisher.read(UUID(headless["written"][0]), BelowRangeVerdictsArtifact)
    root = tmp_path / "interactive replay"
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        assert (
            session.prepare(
                [
                    "--config-home",
                    str(estate.config),
                    "--skill",
                    "dependency-watch",
                    "--mode",
                    "below-range",
                    "--repo",
                    REPO,
                    "--task",
                    str(root),
                ]
            )
            == 0
        )
    task = SessionTask.parse(read_file(root, "task.json"))
    (root / task.output.path).write_bytes(document.payload)
    with contextlib.redirect_stdout(printed):
        assert session.record(["--config-home", str(estate.config), "--task", str(root)]) == 0
    interactive = json.loads(printed.getvalue().splitlines()[-1])
    assert interactive["written"] == headless["written"]


def test_an_order_cannot_record_another_repositorys_review(
    estate: Estate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other_url = "https://github.com/org/another-app"
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        other = uow.repositories.add(Repository(url=other_url, public=True))
        ref = uow.repository_refs.add(
            RepositoryRef(
                repository_id=other.id, name="main", kind="branch", sha=SHA, is_default=True
            )
        )
        uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.REPO_STATE,
                status="completed",
                assessor="fixture",
                assessor_version="1",
                occurred_at=estate.core.clock.now(),
            )
        )
        uow.commit()
    estate.core.services().below_range.scan(other.id, tmp_path / "other-packets")
    executor(tmp_path, monkeypatch)
    code, result = run(estate, "--repo", other_url)
    assert code != 0 and result["reason"] == "bad_request"
    assert estate.core.services().ops.manifest(estate.order_id).sessions == ()
    with SqlTraustUnitOfWork(estate.core.database) as uow:
        assert uow.assessments.list_for_run_order(estate.order_id) == []
