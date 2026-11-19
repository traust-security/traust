"""Submit local assessment and triage orders and record under their actual engine leases."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from contextlib import redirect_stdout
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from uuid import UUID

import yaml
from pydantic import BaseModel
from traust_core.v1.context import Context
from traust_core.v1.models.artifacts import SecurityAuditArtifact, TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.dependencies import FixUptakeState, Version
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import AssetName, JobResult, OrderRequest
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import Ecosystem, SourceType

from traust.cli.__main__ import main as traust
from traust.context import load, load_caller

HERE = Path(__file__).resolve().parent
REPO = "https://github.com/example/smoke-repo"
SHA = "a" * 40
ASSET = AssetName("smoke_triage")
AUTHORED = AssetName("smoke_authored")
STATE = "smoke-prepared.json"
REPORT = "smoke-triage.json"
FINDING_ID = "smoke-finding-id"


class Prepared(BaseModel):
    order_id: UUID
    repository_id: UUID
    ref_id: UUID
    baseline_id: UUID
    finding_id: UUID
    human: str
    validity_id: UUID
    severity_id: UUID


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise SystemExit(f"smoke records: {explanation}")


def rig(prepare: bool) -> tuple[Path, Context]:
    run = Path(os.environ["OPS_SMOKE_RUN"]).resolve(strict=True)
    home = Path(os.environ["TRAUST_CONFIG_HOME"]).resolve(strict=True)
    path = home / "traust.yaml"
    require(
        run.parent.name.startswith(".local-ops-smoke.")
        and run.name == "run"
        and home == run.parent / "config"
        and path.resolve(strict=True) == path,
        "refusing to use anything but the disposable smoke rig",
    )
    cfg = yaml.safe_load(path.read_text())
    require(
        Path(cfg.get("home", "")).resolve() == run / "home"
        and cfg.get("identity", {}).get("trust_local") is True,
        "a private rig home and its own trusted local issuer are required",
    )
    if prepare:
        # Both bindings on a fresh deployment: triage really requires a
        # completed assessment order, and no machine gets an explicit start grant.
        expected = {"assessment": [AUTHORED], "triage": [ASSET]}
        require("recording" not in cfg, "expected a fresh disposable config")
        cfg["recording"] = expected
        path.write_text(yaml.safe_dump(cfg, sort_keys=False))
    return run, load(home)


def machine(core: Context) -> Principal:
    # Verify a fresh short-lived credential without replacing the stored human login.
    if core.identity is None:
        raise SystemExit("smoke records: no identity provider")
    caller = core.identity.authenticate(core.local_issuer.mint("smoke-recorder", machine=True))
    require(caller.is_verified_machine(), "local issuer did not authenticate a machine")
    return caller


def door(*argv: str) -> dict:
    with redirect_stdout(io.StringIO()) as out:
        rc = traust(list(argv))
    require(rc == 0, f"{' '.join(argv[:2])} exited {rc}")
    return json.loads(out.getvalue())


def report(item: dict) -> bytes:
    finding = item["finding"]
    [loc] = item["locations"]
    require((loc["path"], loc["line_start"]) == ("requirements.txt", 1), "wrong fixture location")
    doc = {
        "triage_completed": "2026-10-23",
        "triage_context": {
            "mode": "auto",
            "environment": "Disposable local smoke fixture",
            "votes_per_finding": 3,
            "repo": REPO,
            "harness_version": version("traust"),
        },
        "summary": {
            "input_count": 1, "true_positives": 1, "hardening": 0, "false_positives": 0,
            "undetermined": 0, "duplicates": 0,
            "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [{
            "id": "f001", "title": finding["title"], "verdict": "true_positive",
            "severity": "critical", "file": loc["path"], "line": loc["line_start"],
            "rationale": "Synthetic conflicting machine verdict for requirements.txt:1.",
            "fingerprint": finding["fingerprint"], "fingerprint_algo": finding["fingerprint_algo"],
        }],
    }
    return TriageArtifact.from_document(doc).payload


def submit_authored(core: Context) -> None:
    svc = core.services()
    repo = svc.portfolio.find_repository(HttpsRepoUrl.parse(REPO, core.config.forge_hosts))
    require(repo is not None and repo.id is not None, "expected onboarded fixture repository")
    order = svc.ops.submit(
        OrderRequest(asset=AUTHORED, repository_id=repo.id, priority=45), load_caller(core)
    )
    print(order.id)


def authored(run: Path, core: Context, order_id: UUID) -> None:
    svc = core.services()
    order = svc.ops.get(order_id)
    repo = svc.portfolio.find_repository(HttpsRepoUrl.parse(REPO, core.config.forge_hosts))
    require(repo is not None and order.repository_id == repo.id and order.asset == AUTHORED,
            "authored order is not for the fixture")
    head = svc.portfolio.default_ref(repo.id)
    require(head is not None and head.sha == SHA, "wrong authored report subject")
    raw = (HERE / "authored.json").read_bytes()
    result = svc.assessment.record_secure_code(
        SecurityAuditArtifact.parse(raw),
        head.id,
        version("traust"),
        Provenance(
            run_id=order_id, source=SourceType.VULN_SCAN_REPORT,
            occurred_at=datetime.fromisoformat(os.environ["TRAUST_ORDER_STARTED_AT"]),
        ),
        run_order_id=order_id,
        principal=machine(core),
    )
    [finding] = result.intake.findings.values()
    replay = (run / f"{AUTHORED}.order").exists()
    require(result.intake.created == (() if replay else (finding,)), "wrong authored intake count")
    require(svc.artifacts.payload(result.artifact_id) == raw, "stored authored report bytes differ")
    assessment = svc.assessment.get(result.assessment_id)
    require((assessment.run_order_id, assessment.repository_ref_id) == (order_id, head.id),
            "authored record not bound to the claimed order and fixture head")
    ids = (order_id, result.assessment_id, result.artifact_id, finding)
    print(JobResult.succeeded(tuple(map(str, ids))).model_dump_json())


def prepare(run: Path, core: Context) -> None:
    require(not (run / STATE).exists(), "this run already submitted a triage order")
    human = load_caller(core)
    require(human.is_verified_human(), "prepare needs the rig's verified human login")
    authored_receipt = JobResult.model_validate_json((run / f"{AUTHORED}.receipt").read_bytes())
    order_id, baseline, _, authored_finding = authored_receipt.written
    require(core.services().ops.get(UUID(order_id)).state == "succeeded",
            "the authored assessment must complete before triage")
    prepared = door("triage", "prepare", baseline)
    subject = prepared["subject"]
    [item] = prepared["items"]
    fid = item["finding"]["id"]
    require(fid == authored_finding, "triage input differs from the authored intake receipt")
    occurrence = item["occurrence"]
    require(
        subject["assessment_id"] == baseline
        and (subject["repository_url"], subject["sha"]) == (REPO, SHA)
        and item["finding"]["repository_id"] == subject["repository_id"]
        and (occurrence["assessment_id"], occurrence["finding_id"]) == (baseline, fid),
        "prepared subject or occurrence does not match intake",
    )
    (run / REPORT).write_bytes(report(item))
    judged = {}
    for field, value in (("validity", "false_positive"), ("severity", "medium")):
        # This probes a tie. Giving either statement a stronger evidence grade
        # would test a different policy and mask an incorrect winner.
        saved = door(
            "findings", "record", "--finding", fid, "--decision", field, f"--{field}", value,
            "--rationale", "Human review of the synthetic fixture marker.",
        )
        require(saved["finding_id"] == fid and saved["actor"] == human.ref, "wrong human receipt")
        judged[field] = saved["id"]
    order = core.services().ops.submit(
        OrderRequest(asset=ASSET, repository_id=subject["repository_id"], priority=47), human
    )
    state = Prepared(
        order_id=order.id,
        repository_id=subject["repository_id"],
        ref_id=subject["repository_ref_id"],
        baseline_id=baseline,
        finding_id=fid,
        human=human.ref,
        validity_id=judged["validity"],
        severity_id=judged["severity"],
    )
    (run / STATE).write_text(state.model_dump_json() + "\n")
    (run / FINDING_ID).write_text(fid + "\n")
    print(order.id)


def record(run: Path, core: Context, state: Prepared, order_id: UUID) -> None:
    require(order_id == state.order_id, "not the order submitted by prepare")
    receipt = core.services().findings.decisions.record_triage(
        state.baseline_id, TriageArtifact.parse((run / REPORT).read_bytes()),
        Provenance(run_id=order_id, source=SourceType.TRIAGE_REPORT,
                   occurred_at=datetime.fromisoformat(os.environ["TRAUST_ORDER_STARTED_AT"])),
        run_order_id=order_id, principal=machine(core), checkout=HERE / "repo",
    )
    [decision] = receipt.decisions
    require(
        (decision.finding_id, decision.assessment_id, decision.artifact_id)
        == (state.finding_id, receipt.assessment_id, receipt.artifact_id)
        and (decision.validity, decision.severity) == ("confirmed", "critical"),
        "protected door did not record the expected conflicting verdict",
    )
    ids = (order_id, state.finding_id, receipt.assessment_id, receipt.artifact_id, decision.id)
    result = JobResult.succeeded(tuple(str(i) for i in ids))
    path = run / "smoke-record-receipt.json"
    path.write_text(result.model_dump_json() + "\n")
    print(result.model_dump_json())


def verify(run: Path, core: Context, state: Prepared) -> None:
    svc = core.services()
    fid = state.finding_id
    require(UUID((run / FINDING_ID).read_text().strip()) == fid, "incorrect finding-id handoff")
    order = svc.ops.get(state.order_id)
    require(
        (order.asset, order.repository_id, order.requested_by, order.state)
        == (ASSET, state.repository_id, state.human, "succeeded"),
        "wrong or unfinished triage order",
    )
    rows = svc.findings.history(fid)
    require(len(rows) == 3 and all(d.finding_id == fid for d in rows), "expected three decisions")
    by_id = {row.id: row for row in rows}
    for key, validity, severity in (
        (state.validity_id, "false_positive", None), (state.severity_id, None, "medium"),
    ):
        human = by_id.pop(key, None)
        if human is None:
            raise SystemExit(f"smoke records: missing human decision {key}")
        require(
            (human.actor, human.validity, human.severity, human.evidence_grade)
            == (state.human, validity, severity, None)
            and human.assessment_id is None and human.artifact_id is None,
            "human statement changed",
        )
    [machine_row] = by_id.values()
    require(
        machine_row.actor is None
        and machine_row.evidence_grade is None
        and (machine_row.validity, machine_row.severity) == ("confirmed", "critical")
        and machine_row.assessment_id is not None and machine_row.artifact_id is not None,
        "no persisted conflicting machine triage",
    )
    receipt = JobResult.model_validate_json((run / "smoke-record-receipt.json").read_bytes())
    ids = (order.id, fid, machine_row.assessment_id, machine_row.artifact_id, machine_row.id)
    require(receipt.written == tuple(str(i) for i in ids), "stored IDs differ from record receipt")
    triage = svc.assessment.get(machine_row.assessment_id)
    [artifact] = svc.assessment.list_artifacts(triage.id, "triage")
    require(
        (triage.kind, triage.run_order_id, triage.repository_ref_id, triage.baseline_assessment_id)
        == ("triage", order.id, state.ref_id, state.baseline_id)
        and (artifact.id, artifact.assessment_id) == (machine_row.artifact_id, triage.id)
        and artifact.digest == hashlib.sha256((run / REPORT).read_bytes()).hexdigest(),
        "machine assessment, order or artifact binding mismatch",
    )
    view = svc.findings.get(fid)
    disposition = view.disposition
    require(disposition is not None and disposition.conflict, "expected a recorded conflict")
    winners = (disposition.validity, disposition.severity, view.effective_severity)
    require(
        winners == ("false_positive", "medium", "medium"),
        f"ungraded conflict on {fid}: human false_positive/medium did not win; got {winners}",
    )
    print(f"smoke: verified three decisions on {fid}; human false_positive/medium wins")


def verify_coverage(core: Context) -> None:
    svc = core.services()
    url = HttpsRepoUrl.parse("https://github.com/example/smoke-containers", core.config.forge_hosts)
    repo = svc.portfolio.find_repository(url)
    require(repo is not None, "Docker-only fixture not onboarded")
    ref = svc.portfolio.default_ref(repo.id)
    require(ref is not None and ref.sha == SHA, "Docker-only fixture head not observed")
    require(ref.manifest_sbom_assessment_id is not None and not svc.exposure.dependencies(ref.id),
            "Docker-only fixture needs a completed, empty manifest scan")
    [artifact] = svc.assessment.list_artifacts(ref.manifest_sbom_assessment_id, "manifest-coverage")
    evidence = json.loads(svc.artifacts.payload(artifact.id))
    require(
        evidence["assessment_id"] == str(ref.manifest_sbom_assessment_id)
        and evidence["sbom_id"] == str(ref.manifest_sbom_id)
        and evidence["tool"]["name"] == "syft" and bool(evidence["tool"]["version"])
        and evidence["unresolved"] == {
            "docker": {"build/images/Dockerfile": "unsupported-manifest"}
        },
        "missing scan-bound Docker coverage",
    )
    uptake = svc.exposure.consumes_fix(ref.id, Ecosystem.DOCKER, "base", Version("1.2.4"))
    require(uptake.state == FixUptakeState.NOT_OBSERVED, f"unresolved base read as {uptake.state}")
    print("smoke: nested external base recorded as unresolved; fix uptake not_observed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("submit-authored", "prepare", "worker", "verify", "verify-coverage"):
        commands.add_parser(name)
    for name in ("authored", "record"):
        commands.add_parser(name).add_argument("order_id", type=UUID)
    args = parser.parse_args()
    run, core = rig(args.command == "submit-authored")
    if args.command == "verify-coverage":
        verify_coverage(core)
        return
    if args.command == "submit-authored":
        submit_authored(core)
    elif args.command == "authored":
        authored(run, core, args.order_id)
    elif args.command == "prepare":
        prepare(run, core)
    elif args.command == "worker":
        print(machine(core).ref)
    else:
        state = Prepared.model_validate_json((run / STATE).read_bytes())
        if args.command == "record":
            record(run, core, state, args.order_id)
        else:
            verify(run, core, state)


if __name__ == "__main__":
    main()
