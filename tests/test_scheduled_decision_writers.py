"""Execute the shipped pack argv against a real lease, substituting only fixture evidence."""

from __future__ import annotations

import io
import json
import subprocess
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import yaml
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderRequest, WorkerId
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from tests.test_validation_record import recording as evidence  # noqa: F401
from traust.cli import session
from traust.cli.__main__ import main
from traust.cli._doors import ORDER_STARTED_ENV, RUN_ORDER_ENV
from traust.context import load
from traust.ops.intake import RescanEventIntakeMaterializer
from traust.paths import SECURITY_PACK_DIR, skill_dir

VALIDATE = "external_report_validation"
VERIFY = "verify_remediation"
URL = "https://github.com/example/validation-fixture"
PACK = SECURITY_PACK_DIR / "assets.yaml"


def configure(home, store, *, ledger):
    home.mkdir(exist_ok=True)
    cfg = {
        "home": str(store),
        "identity": {"trust_local": True},
        "recording": {"validation": [VALIDATE], "verification": [VERIFY]},
    }
    if ledger:
        cfg["ledger"] = {}
    (home / "traust.yaml").write_text(yaml.safe_dump(cfg))
    return load(home)


def lease(core, asset, repo_id, root, principal, worker):
    services = core.services()
    if asset == VALIDATE:
        feed = root / "events.jsonl"
        feed.write_text(json.dumps({
            "source": "external-report", "repo": URL, "report": "synthetic-report",
            "targets": "synthetic-scope",
        }))
        with core.repository_observation() as observation:
            result = RescanEventIntakeMaterializer(
                services, observation.query, principal, feed
            ).materialize(AssetRequest(asset="rescan_event_intake", run_id="event-intake"))
        orders = [services.ops.get(UUID(id_)) for id_ in result.written]
        assert {o.asset for o in orders} == {VALIDATE, "external_report_audit"}
        order = next(o for o in orders if o.asset == VALIDATE)
        services.ops.request_approval(order.id)
        services.ops.approve(order.id, principal)
    else:
        order = services.ops.plan(OrderRequest(asset=asset, priority=50, repository_id=repo_id), principal)
        services.ops.admit(order.id)
    claimed = services.ops.claim(worker, timedelta(minutes=5), order_id=order.id)
    assert claimed is not None and claimed.repository_id == repo_id
    return claimed


def validation_producer(fixture, writer_home, mp):
    """The unattended producer and record door, with zero real steps or target providers."""
    import runpy

    from adapters import StepResult
    from ingest import Finding, Normalized
    from scope import ClusterScope, Scope

    runner = runpy.run_path(str(skill_dir("validate-findings") / "run.py"))
    source = fixture["report"]["source_reports"][0]
    finding = Finding(id="f001", source_id="f001", source_report_path=source["path"],
                      title="Fixture", severity="high")
    inputs = Normalized(target_name="fixture", source_dir="opaque:fixture", source_reports=[source], findings=[finding])
    scope = Scope(environment="lab")
    scope.modes.add("explicit")
    scope.clusters["fixture"] = ClusterScope(context="fixture", namespaces=["fixture"])
    mp.setattr(runner["ing"], "ingest", lambda *a, **kw: inputs)
    mp.setattr(runner["sc"], "build", lambda **kw: scope)
    mp.setattr(runner["pl"], "build_plan", lambda *a, **kw: ([], []))
    mp.setattr(runner["pl"], "write_plan", lambda *a, **kw: None)
    mp.setattr(runner["ex"], "preflight", lambda *_: [], raising=False)
    observed = StepResult(step_id="fixture", adapter="k8s", verb="get", target={},
                          classification="safe", verdict="confirmed", observed="success", finding_ref="f001")
    audit = SimpleNamespace(sha256=lambda: "b" * 64)
    mp.setattr(runner["ex"], "run", lambda *a, **kw: ([observed], audit))
    root = fixture["root"]
    args = ["synthetic-report", "--config-home", str(writer_home), "--targets", "synthetic-scope",
            "--replay-only", "--out", str(root / "output")]
    for name, value in (
        ("record-bindings", fixture["bindings"]),
        ("finding-assessments", {"f001": {"evidence_grade": "E1"}}),
        ("target-attestation", fixture["report"]["metadata"]["target_attestation"]),
    ):
        path = root / f"{name}.json"
        path.write_text(json.dumps(value))
        args.extend((f"--{name}", str(path)))
    return runner["main"](args)


def verification_fixture(core, fixture, repo_id):
    raw = (Path(__file__).parent / "fixtures/remediation/verification-report.json").read_text()
    doc = json.loads(raw.replace("FINDING_ID", str(fixture["finding_id"])))
    doc["metadata"].update(repository=URL, patched_ref="main", original_commit="a" * 40)
    with SqlTraustUnitOfWork(core.database) as uow:
        # A bare source commit does not establish ancestry. Observe it on main
        # before moving the default head to the patched commit.
        uow.repository_refs.add(RepositoryRef(
            repository_id=repo_id, name="main", kind="branch",
            sha=doc["metadata"]["original_commit"], is_default=True,
        ))
        head = uow.repository_refs.add(RepositoryRef(repository_id=repo_id, name="main", kind="branch",
                                                    sha=doc["metadata"]["patched_commit"], is_default=True))
        uow.assessments.add(Assessment(repository_ref_id=head.id, kind=AssessmentKind.REPO_STATE,
                                       status="completed", assessor="fixture", assessor_version="1",
                                       occurred_at=core.clock.now()))
        uow.commit()
    path = fixture["root"] / "verification.json"
    path.write_text(json.dumps(doc))
    return path


@pytest.mark.parametrize("asset", [VALIDATE, VERIFY])
@pytest.mark.parametrize("writer_ledger", [True, False], ids=["writer-ledger", "no-writer-ledger"])
def test_pack_command_uses_the_repository_lease_and_the_writers_own_ledger(
    evidence, tmp_path, monkeypatch, capsys, asset, writer_ledger  # noqa: F811
):
    from traust_core.v1.errors import ServiceError

    planner_home, writer_home = evidence["config"], tmp_path / "writer"
    core = configure(planner_home, tmp_path / "store", ledger=True)
    configure(writer_home, tmp_path / "store", ledger=writer_ledger)
    services = core.services()
    repo = services.portfolio.find_repository(URL)
    machine = core.local_issuer.mint("normal-pack-test", machine=True)
    token = tmp_path / "recorder-token"
    token.touch(mode=0o600)
    token.write_text(machine.token.get_secret_value())
    monkeypatch.setenv("TRAUST_RECORDER_TOKEN_FILE", str(token))
    worker = WorkerId(core.identity.authenticate(machine).ref)
    approver = core.identity.authenticate(core.local_issuer.mint("operator@example.com"))
    order = lease(core, asset, repo.id, tmp_path, approver, worker)
    monkeypatch.setenv(ORDER_STARTED_ENV, order.started_at.isoformat())
    monkeypatch.delenv(RUN_ORDER_ENV, raising=False)
    monkeypatch.setattr(session, "resolve_model", lambda role: "fixture-model")
    spec = yaml.safe_load(PACK.read_text())["assets"][asset]
    assert spec["partitions"] == "dynamic:repo"
    assert set(spec["requires"]["config"]) >= {"identity", "ledger"}
    params = {"role": spec["model"]["role"], "repo_url": URL, "run_id": str(order.id), "worker": worker}
    argv = [s.format_map(params) for s in spec["run"][3:]]
    argv.extend(("--config-home", str(planner_home)))
    if asset == VERIFY:
        monkeypatch.setattr(session, "session", lambda *_: pytest.fail("no observed head: no session"))
        assert main(argv) == 0
        skipped = json.loads(capsys.readouterr().out)
        assert skipped["outcome"] == "succeeded" and skipped["written"] == []
        path = verification_fixture(core, evidence, repo.id)
        assert services.verification.sweep([repo.id]).queued
    attempts = []

    def fixture_executor(command, skill, env):
        assert env[RUN_ORDER_ENV] == str(order.id) and env[ORDER_STARTED_ENV] == order.started_at.isoformat()
        assert env["TRAUST_CONFIG_HOME"] == str(planner_home)
        with monkeypatch.context() as mp, redirect_stdout(io.StringIO()) as out:
            mp.setenv(RUN_ORDER_ENV, env[RUN_ORDER_ENV])
            if asset == VALIDATE:
                assert command[-1] == "/validate-findings synthetic-report --targets synthetic-scope --auto --replay-only"
                try:
                    code = validation_producer(evidence, writer_home, mp)
                except ServiceError as error:
                    assert not writer_ledger and "requires a ledger" in str(error)
                    code = 2
                if not code:
                    result = json.loads(out.getvalue())["recording"]
                    companion = UUID(result["evidence_artifact_ids"][0])
                    origin = services.validation.evidence(companion).provenance
                    provenance_path = tmp_path / "run-provenance.json"
                    provenance_path.write_text(origin.model_dump_json())
                    with redirect_stdout(io.StringIO()) as replay:
                        assert main([
                            "validation", "record", "--config-home", str(writer_home),
                            "--provenance", str(provenance_path),
                            "--bindings", str(tmp_path / "record-bindings.json"),
                            "--target-attestation", str(tmp_path / "target-attestation.json"),
                            "--report", str(tmp_path / "output/fixture-validation.json"),
                        ]) == 0
                    assert json.loads(replay.getvalue()) == result
                    assert (origin.run_id, origin.occurred_at) == (order.id, order.started_at)
            else:
                assert command[-1] == f"/verify-remediation full-sweep --repo-url {URL}"
                args = ["remediation", "verify-record", str(path), "--config-home", str(writer_home)]
                code = main(args)
                if not code:
                    first = json.loads(out.getvalue())
                    with redirect_stdout(io.StringIO()) as replay:
                        assert main(args) == 0
                    assert json.loads(replay.getvalue()) == first
        attempts.append(code)
        # A zero executor exit alone must never turn a refused write into successful work.
        return subprocess.CompletedProcess(command, 0), ()

    monkeypatch.setattr(session, "session", fixture_executor)
    code = main(argv)
    captured = capsys.readouterr()
    result = JobResult.model_validate_json(captured.out)
    if writer_ledger:
        monkeypatch.setattr(session, "session", lambda *_: pytest.fail("already recorded"))
        assert main(argv) == 0
        assert JobResult.model_validate_json(capsys.readouterr().out).written == result.written
    finished = services.ops.complete(order.id, worker, result)
    runs = services.assessment.list_for_order(order.id)
    history = services.findings.history(evidence["finding_id"])
    if writer_ledger:
        assert (attempts, code, finished.state) == ([0], 0, "succeeded"), captured.err
        [recorded] = runs
        assert result.written == (str(recorded.id),) and recorded.run_order_id == order.id
        assert recorded.occurred_at == order.started_at
        [said] = [d for d in history if d.assessment_id == recorded.id]
        with SqlTraustUnitOfWork(core.database) as uow:
            assert uow.events.find_by_decision(said.id) is not None
    else:
        assert attempts == [2] and code != 0 and finished.state == "failed"
        assert result.reason == "session-output-invalid" and not result.written
        assert runs == history == [] and not services.ledger.layers(repo.id)
        if asset == VERIFY:
            assert "requires a ledger" in captured.err


@pytest.mark.parametrize(
    ("bound", "started", "override"),
    [("", None, None), ("manual", None, None), (None, "invalid", None),
     ("00000000-0000-4000-8000-000000000001", "invalid", None),
     ("00000000-0000-4000-8000-000000000001", None, UUID(int=2))],
)
def test_partial_or_conflicting_claim_never_generates_standalone_provenance(
    monkeypatch, bound, started, override
):
    from traust_core.v1.errors import ValidationError
    from traust_core.v1.models.vocabulary import SourceType

    from traust.cli._doors import report_provenance

    for name, value in ((RUN_ORDER_ENV, bound), (ORDER_STARTED_ENV, started)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        report_provenance(override, SourceType.VERIFICATION_REPORT)
