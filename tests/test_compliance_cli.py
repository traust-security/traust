"""`traust compliance …`: the CLI layer only. Arguments become the
`ComplianceService` door calls; a refused input is exit 2. The doors are traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.artifacts import (
    AdrRegistryArtifact,
    ComplianceAssessmentArtifact,
    ComplianceMappingArtifact,
    ComplianceScopeArtifact,
    OrgParametersArtifact,
)
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.compliance import (
    AwaitingReview,
    ComplianceScope,
    InventorySnapshot,
    RunCalibration,
    ScopeFilter,
)
from traust_core.v1.models.vocabulary import ComplianceFramework
from traust_core.v1.services.compliance import ComplianceService
from traust_core.v1.services.lint import LintAction, LintReport, LintRuleId, Violation

from tests.compliance_paths import compliance_registry
from traust.cli import compliance

DECLARATION = {
    "version": 1,
    "updated": "2026-10-24",
    "boundaries": {
        "widget-prod": {
            "frameworks": ["nist-800-53-rev5"],
            "resolves_via": "explicit",
            "include": [{"repo": "acme/widget", "reason": "the service"}],
            "declared_by": "jdoe",
            "declared_at": "2026-10-24",
        }
    },
}


def scope(boundary: str) -> ComplianceScope:
    return ComplianceScope(
        scope_id=uuid.uuid4(),
        boundary=boundary,
        frameworks=("nist-800-53-rev5",),
        resolves_via="explicit",
        declared_by="jdoe",
        declared_at="2026-10-24",
    )


WIDGET, OTHER = scope("widget-prod"), scope("other")
CALLER = object()


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((*args, *kwargs.items()))
        result = self.result(*args) if callable(self.result) else self.result
        if isinstance(result, Exception):
            raise result
        return result


class Dumps:
    def __init__(self, body: dict) -> None:
        self.body = body

    def model_dump_json(self, **_: Any) -> str:
        return json.dumps(self.body)


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    pages = {
        None: Page(items=(OTHER,), next="c1"),
        "c1": Page(items=(WIDGET,), next=None),
    }
    stub = SimpleNamespace(
        set_scope=Door(Dumps({"boundary": "widget-prod"})),
        scopes=Door(lambda f, page: pages[page.cursor]),
        get_scope=Door(lambda scope_id: WIDGET),
        resolve=Door(Dumps({"members": []})),
    )
    services = SimpleNamespace(compliance=stub)
    monkeypatch.setattr(Context, "services", lambda self: services)
    monkeypatch.setattr(compliance, "load_caller", lambda core: CALLER)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(op: str, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = getattr(compliance, op)(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.fixture
def declaration(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(DECLARATION))
    return path


@pytest.mark.parametrize(("flags", "replace"), [((), False), (("--replace",), True)])
def test_declare_records_the_document_as_the_verified_caller(
    doors: SimpleNamespace, home: Path, declaration: Path, flags: tuple[str, ...], replace: bool
) -> None:
    rc, out = call("declare", home, str(declaration), *flags)
    assert (rc, out) == (0, {"boundary": "widget-prod"})
    ((doc, caller, kwarg),) = doors.set_scope.calls
    assert isinstance(doc, ComplianceScopeArtifact) and caller is CALLER
    assert kwarg == ("replace", replace)


def test_declaring_an_existing_boundary_is_exit_2(
    doors: SimpleNamespace, home: Path, declaration: Path
) -> None:
    doors.set_scope.result = ConflictError("boundary 'widget-prod' already declared")
    rc, err = call("declare", home, str(declaration))
    assert rc == 2 and "already declared" in err


def test_a_declaration_that_fails_its_schema_is_exit_2(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yaml"
    entry = {**DECLARATION["boundaries"]["widget-prod"], "frameworks": ["nist-800-53-r5"]}
    bad.write_text(yaml.safe_dump({**DECLARATION, "boundaries": {"widget-prod": entry}}))
    rc, err = call("declare", home, str(bad))
    assert rc == 2 and "frameworks" in err
    assert not doors.set_scope.calls


@pytest.mark.parametrize(
    ("flags", "wanted"),
    [
        ((), ScopeFilter()),
        (("--draft",), ScopeFilter(draft=True)),
        (("--signed", "--product", "widget"), ScopeFilter(draft=False, product="widget")),
        (("--framework", "soc2-tsc"), ScopeFilter(framework="soc2-tsc")),
    ],
)
def test_scopes_pass_the_filter_and_page(
    doors: SimpleNamespace, home: Path, flags: tuple[str, ...], wanted: ScopeFilter
) -> None:
    rc, out = call("scopes", home, *flags)
    assert rc == 0 and out["next"] == "c1"
    assert doors.scopes.calls == [(wanted, PageRequest())]


def test_resolve_finds_a_boundary_by_name_across_pages(doors: SimpleNamespace, home: Path) -> None:
    rc, out = call("resolve", home, "widget-prod")
    assert (rc, out) == (0, {"members": []})
    assert doors.resolve.calls == [(WIDGET.scope_id,)]
    assert len(doors.scopes.calls) == 2


def test_resolve_takes_a_scope_id(doors: SimpleNamespace, home: Path) -> None:
    rc, _ = call("resolve", home, str(WIDGET.scope_id))
    assert rc == 0
    assert doors.get_scope.calls == [(WIDGET.scope_id,)]
    assert not doors.scopes.calls


def test_an_undeclared_boundary_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = call("resolve", home, "nope")
    assert rc == 2 and "'nope'" in err
    assert not doors.resolve.calls


def test_a_superseded_declaration_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.resolve.result = ConflictError("compliance scope is superseded")
    rc, err = call("resolve", home, str(WIDGET.scope_id))
    assert rc == 2 and "superseded" in err


ASSESSMENT = {
    "metadata": {
        "artifact": "compliance-assessment",
        "harness_version": "0.99.0-test",
        "scope_id": str(WIDGET.scope_id),
        "target": {"kind": "product", "repos": ["acme/widget"]},
        "frameworks": [{"id": "nist-800-53-rev5"}],
        "skipped_frameworks": {},
        "registry_hash": "b" * 64,
        "generated_at": "2026-10-24T00:00:00Z",
    },
    "coverage": {
        "nist-800-53-rev5": {
            "total_in_scope": 1,
            "deterministic": 0,
            "evidence_review": 0,
            "organizational": 1,
            "satisfied": 0,
            "not_satisfied": 0,
            "not_applicable": 0,
            "not_assessed": 1,
        }
    },
    "results": [
        {
            "framework": "nist-800-53-rev5",
            "control_id": "at-2",
            "classification": "organizational",
            "verdict": "not_assessed",
            "verdict_source": "check",
            "reason": "organizational — out of technical scope",
        }
    ],
}
DRAFT = ComplianceAssessmentArtifact.from_document(ASSESSMENT)


@pytest.fixture
def runner(doors: SimpleNamespace) -> SimpleNamespace:
    evaluated = SimpleNamespace(document=DRAFT, evidence=("c" * 64,), failures=())
    awaiting = AwaitingReview(
        framework="nist-800-53-rev5", control_id="sc-8", evidence_request="TLS"
    )
    doors.evaluate = Door(evaluated)
    doors.prepare = Door(SimpleNamespace(assessment=ASSESSMENT, awaiting=(awaiting,)))
    doors.render_assessment = Door(ComplianceService.render_assessment)
    doors.check = Door(LintReport())
    doors.record = Door(Dumps({"recorded": True}))
    doors.calibrate = Door(RunCalibration(controls=1))
    return doors


def write(tmp_path: Path, name: str, body: Any) -> Path:
    path = tmp_path / name
    path.write_text(body if isinstance(body, str) else json.dumps(body))
    return path


def test_policy_records_the_mapping_or_the_adr_registers(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    published = SimpleNamespace(artifact_id=uuid.uuid4())
    doors.record = Door(published)
    mapping = yaml.safe_load(compliance_registry().read_text())
    registers = {
        "version": 1,
        "registers": [
            {
                "name": "arch",
                "repo": "https://github.com/acme/architecture",
                "paths": ["decisions"],
                "pin": "a" * 40,
                "governs": ["product:widget"],
            }
        ],
    }
    for kind, body, artifact in (
        ("mapping", mapping, ComplianceMappingArtifact),
        ("adr-registry", registers, AdrRegistryArtifact),
    ):
        rc, out = call(
            "policy", home, kind, str(write(tmp_path, f"{kind}.yaml", yaml.safe_dump(body)))
        )
        assert (rc, out) == (0, {"artifact_id": str(published.artifact_id)})
        assert isinstance(doors.record.calls[-1][0], artifact)


def test_policy_records_the_org_parameters(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    published = SimpleNamespace(artifact_id=uuid.uuid4())
    doors.record = Door(published)
    body = {
        "version": 1,
        "declared_by": "platform-security",
        "parameters": {
            "allowed_data_regions": {"value": ["us-east-1"], "controls": ["gdpr:art-44"]}
        },
    }
    document = write(tmp_path, "org-parameters.yaml", yaml.safe_dump(body))
    rc, out = call("policy", home, "org-parameters", str(document))
    assert (rc, out) == (0, {"artifact_id": str(published.artifact_id)})
    assert isinstance(doors.record.calls[-1][0], OrgParametersArtifact)


def test_policy_refuses_org_parameters_off_their_schema(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    doors.record = Door(SimpleNamespace(artifact_id=uuid.uuid4()))
    document = write(tmp_path, "org-parameters.yaml", yaml.safe_dump({"version": 1}))
    rc, _ = call("policy", home, "org-parameters", str(document))
    assert rc == 2 and doors.record.calls == []


def test_evaluate_writes_the_draft_and_lists_what_awaits_the_agent_pass(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    khs = write(tmp_path, "khs.json", {"facts": []})
    inventory = write(
        tmp_path,
        "inv.json",
        {
            "metadata": {"collector": "collect_cloud_inventory.py"},
            "resources": [{"id": "b1"}],
            "gaps": [],
        },
    )
    crypto = write(
        tmp_path,
        "crypto.json",
        {"facts": [{"probe_id": "CRYPTO_GODEBUG_TLS_KILLSWITCH", "provider": "go", "detail": "x"}]},
    )
    out = tmp_path / "out" / "draft.json"
    rc, body = call(
        "evaluate",
        home,
        "widget-prod",
        "--frameworks",
        "nist-800-53-rev5, soc2-tsc",
        "--trust-categories",
        "security",
        "--collector",
        f"scan_k8s_hardening={khs}",
        "--inventory",
        str(inventory),
        "--crypto",
        str(crypto),
        "--out",
        str(out),
    )
    assert rc == 0
    assert (
        body["awaiting"][0]["control_id"] == "sc-8" and body["gate"] == [] and body["evidence"] == 1
    )
    assert out.read_bytes() == DRAFT.payload
    markdown = out.with_suffix(".md")
    assert Path(body["markdown"]) == markdown
    assert markdown.read_bytes() == ComplianceService.render_assessment(DRAFT)
    document = ComplianceAssessmentArtifact.from_document(json.loads(out.read_bytes()))
    assessment = json.loads(document.payload)
    (result,) = assessment["results"]
    assert result["classification"] == "organizational"
    assert result["verdict"] == "not_assessed" and result["verdict_source"] == "check"
    coverage = assessment["coverage"]["nist-800-53-rev5"]
    assert coverage["not_assessed"] == 1
    assert coverage["satisfied"] == coverage["not_satisfied"] == 0
    ((request,),) = runner.evaluate.calls
    assert request.scope_id == WIDGET.scope_id
    assert request.frameworks == ("nist-800-53-rev5", "soc2-tsc")
    assert request.trust_categories == ("security",)
    assert request.snapshots == {"scan_k8s_hardening": {"facts": []}}
    assert (
        request.inventory.snapshot_id == InventorySnapshot.of("x", [{"id": "b1"}], []).snapshot_id
    )
    assert request.crypto[0].provider == "go"


def test_evaluate_all_frameworks_and_a_failed_gate_is_exit_1(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    runner.evaluate.result.failures = ("results[0]: narrative verdict",)
    rc, body = call(
        "evaluate", home, "widget-prod", "--frameworks", "all", "--out", str(tmp_path / "d.json")
    )
    assert rc == 1 and body["gate"] == ["results[0]: narrative verdict"]
    ((request,),) = runner.evaluate.calls
    assert set(request.frameworks) == set(ComplianceFramework)
    assert (tmp_path / "d.md").read_bytes() == ComplianceService.render_assessment(DRAFT)


def test_evaluate_refuses_a_malformed_snapshot(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    bad = write(tmp_path, "inv.json", {"resources": []})
    rc, err = call(
        "evaluate", home, "widget-prod", "--inventory", str(bad), "--out", str(tmp_path / "d.json")
    )
    assert rc == 2 and "metadata" in err
    assert not runner.evaluate.calls


def test_evaluate_can_choose_the_markdown_path_without_overwriting_the_json(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    document = tmp_path / "draft.json"
    markdown = tmp_path / "reports" / "controls.md"
    rc, result = call(
        "evaluate", home, "widget-prod", "--out", str(document), "--markdown", str(markdown)
    )
    assert rc == 0
    assert document.read_bytes() == DRAFT.payload
    assert markdown.read_bytes() == ComplianceService.render_assessment(DRAFT)
    assert Path(result["markdown"]) == markdown


def test_evaluate_refuses_colliding_json_and_markdown_before_writing(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    document = tmp_path / "draft.json"
    document.write_text("existing")
    rc, _ = call(
        "evaluate", home, "widget-prod", "--out", str(document), "--markdown", str(document)
    )
    assert rc == 2
    assert document.read_text() == "existing"
    assert not runner.evaluate.calls


@pytest.mark.parametrize("kind", ["findings_db", "crypto_audit", "cloud_inventory"])
def test_evaluate_refuses_a_collector_core_builds(
    runner: SimpleNamespace, home: Path, tmp_path: Path, kind: str
) -> None:
    snapshot = write(tmp_path, "s.json", {})
    rc, err = call(
        "evaluate", home, "widget-prod", "--collector", f"{kind}={snapshot}", "--out", "d.json"
    )
    assert rc == 2 and f"--collector {kind}" in err
    assert not runner.evaluate.calls


def test_evidence_hashes_the_artifact_into_the_bundle(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    doors.add_evidence = Door(Dumps({"sha256": "d" * 64}))
    artifact = write(tmp_path, "attestation.json", {"statement": "TLS 1.3"})
    rc, out = call("evidence", home, str(artifact), "--locator", "attestation:tls")
    assert (rc, out) == (0, {"sha256": "d" * 64})
    assert doors.add_evidence.calls == [
        ("human_artifact", "attestation:tls", {"statement": "TLS 1.3"})
    ]
    rc, err = call("evidence", home, str(write(tmp_path, "x.json", "not json")), "--locator", "x")
    assert rc == 2 and "x.json" in err


def test_check_is_exit_1_on_any_violation(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    draft = write(tmp_path, "a.json", ASSESSMENT)
    assert call("check", home, str(draft)) == (0, {"violations": []})
    runner.check.result = LintReport(
        violations=(
            Violation(
                rule=LintRuleId("compliance.citations"),
                item="results[0]",
                message="m",
                action=LintAction.REVIEW,
            ),
        )
    )
    rc, out = call("check", home, str(draft))
    assert rc == 1 and out["violations"][0]["message"] == "m"


def test_record_records_the_assessment(runner: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    rc, out = call("record", home, str(write(tmp_path, "a.json", ASSESSMENT)))
    assert (rc, out) == (0, {"recorded": True})
    ((doc, provenance),) = runner.record.calls
    assert json.loads(doc.payload) == ASSESSMENT and provenance.artifact is None


def test_latest_is_null_before_any_record_and_else_carries_the_posture(
    doors: SimpleNamespace, home: Path
) -> None:
    doors.latest = Door(None)
    assert call("latest", home, "widget-prod", "--framework", "nist-800-53-rev5") == (0, "")
    recorded = SimpleNamespace(
        model_dump=lambda **_: {"scope_id": "s"},
        posture=lambda: SimpleNamespace(model_dump=lambda **_: {"coverage": {}}),
    )
    doors.latest = Door(recorded)
    rc, out = call("latest", home, "widget-prod", "--framework", "nist-800-53-rev5")
    assert (rc, out) == (0, {"assessment": {"scope_id": "s"}, "posture": {"coverage": {}}})
    assert doors.latest.calls == [(WIDGET.scope_id, "nist-800-53-rev5")]


def test_calibrate_scores_on_the_key_and_a_divergence_is_exit_1(
    runner: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    key = write(tmp_path, "key.json", {"expected": {"nist-800-53-rev5": {"at-2": "not_assessed"}}})
    rc, out = call("calibrate", home, "widget-prod", "--key", str(key))
    assert rc == 0 and out["passed"] is True
    ((_, passed_key),) = runner.calibrate.calls
    assert passed_key.expected == {"nist-800-53-rev5": {"at-2": "not_assessed"}}
    runner.calibrate.result = RunCalibration(controls=1, divergences=("coverage blocks differ",))
    rc, out = call("calibrate", home, "widget-prod")
    assert rc == 1 and out["divergences"] == ["coverage blocks differ"]
    assert runner.calibrate.calls[-1][1] is None
