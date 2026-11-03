"""`traust dashboard view`: the CLI layer only. Scope flags become one `ViewFilter`, then one
`InsightService.publish`; `<stem>.{md,html,json}` land where asked. Views are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models import insight
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import FindingsTrend, RenderedView, ViewFilter, ViewName

from tests.test_products_doors import _postgres
from traust.cli import dashboard_view
from traust.context import SLA_POLICY

ALPHA = SimpleNamespace(id=uuid.uuid4(), slug="alpha", name="Alpha")
TEAM = uuid.uuid4()
AS_OF = datetime(2026, 9, 30, tzinfo=UTC)
RENDERED = RenderedView(
    view=ViewName.FINDINGS_TREND,
    stem="findings-trend",
    model=FindingsTrend(as_of=AS_OF, repositories=2),
    markdown="# Findings trend\n",
    html="<!doctype html><title>Findings trend</title>",
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
def publish(monkeypatch: pytest.MonkeyPatch) -> Door:
    door = Door(RENDERED)
    services = SimpleNamespace(
        insight=SimpleNamespace(publish=door),
        portfolio=SimpleNamespace(find_product=lambda slug: {"alpha": ALPHA}.get(str(slug))),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = dashboard_view.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_no_scope_is_one_publish_and_three_files(publish: Door, home: Path, tmp_path: Path) -> None:
    out = tmp_path / "trends"
    rc, answer = run(home, "findings-trend", "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.FINDINGS_TREND, ViewFilter())]
    assert sorted(p.name for p in out.iterdir()) == [
        "findings-trend.html",
        "findings-trend.json",
        "findings-trend.md",
    ]
    assert (out / "findings-trend.md").read_text() == RENDERED.markdown
    assert json.loads((out / "findings-trend.json").read_text())["repositories"] == 2
    assert answer["model"]["repositories"] == 2


def test_loc_writes_the_lines_of_code_view(publish: Door, home: Path, tmp_path: Path) -> None:
    publish.result = RenderedView(
        view=ViewName.LOC,
        stem="lines-of-code",
        model=insight.LocDashboard(code=120, total=150),
        markdown="# Lines of code\n",
        html="<!doctype html><title>Lines of code</title>",
    )
    out = tmp_path / "dashboards"
    rc, answer = run(home, "loc", "--product", "alpha", "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.LOC, ViewFilter(product_ids=(ALPHA.id,)))]
    assert sorted(p.name for p in out.iterdir()) == [
        "lines-of-code.html",
        "lines-of-code.json",
        "lines-of-code.md",
    ]
    assert answer["model"]["code"] == 120


@pytest.mark.parametrize(
    ("view", "stem", "model"),
    [
        (ViewName.PQC, "pqc-readiness", insight.PqcDashboard()),
        (ViewName.PQC_PORTFOLIO, "pqc-portfolio-roll-up", insight.PqcPortfolio()),
    ],
)
def test_the_pqc_views_replace_the_skills_report_scripts(
    publish: Door, home: Path, tmp_path: Path, view: ViewName, stem: str, model: Any
) -> None:
    publish.result = RenderedView(
        view=view, stem=stem, model=model, markdown="# PQC\n", html="<title>PQC</title>"
    )
    out = tmp_path / "pqc"
    rc, _ = run(home, view.value, "--product", "alpha", "--out", str(out))
    assert rc == 0
    assert publish.calls == [(view, ViewFilter(product_ids=(ALPHA.id,)))]
    assert sorted(p.name for p in out.iterdir()) == [f"{stem}.{x}" for x in ("html", "json", "md")]


def test_the_vendor_roadmap_replaces_the_vendor_tracker_script(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    model = insight.PqcVendorRoadmap(
        claims_artifact_id=uuid.uuid4(),
        version=1,
        updated="2026-07-19",
        repositories=3,
        unmeasured=1,
        blocked_external=("https://github.com/acme/widget",),
    )
    publish.result = RenderedView(
        view=ViewName.PQC_VENDORS,
        stem="pqc-vendor-roadmap",
        model=model,
        markdown="# PQC vendor roadmap\n",
        html="<title>PQC vendor roadmap</title>",
    )
    out = tmp_path / "pqc"
    rc, answer = run(home, "pqc-vendors", "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.PQC_VENDORS, ViewFilter())]
    assert sorted(p.name for p in out.iterdir()) == [
        f"pqc-vendor-roadmap.{x}" for x in ("html", "json", "md")
    ]
    assert answer["model"]["blocked_external"] == ["https://github.com/acme/widget"]


def test_scope_window_and_bucket_go_into_one_filter(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    since = datetime(2026, 1, 1, tzinfo=UTC)
    argv = ("--product", "alpha", "--product", "alpha", "--team-id", str(TEAM))
    rc, _ = run(
        home,
        "program",
        *argv,
        "--since",
        since.isoformat(),
        "--as-of",
        AS_OF.isoformat(),
        "--bucket",
        "week",
        "--out",
        str(tmp_path),
    )
    assert rc == 0
    assert publish.calls == [
        (
            ViewName.PROGRAM,
            ViewFilter(
                product_ids=(ALPHA.id,),
                team_ids=(TEAM,),
                as_of=AS_OF,
                window=TimeWindow(start=since, end=AS_OF),
                bucket=TimeBucket.WEEK,
            ),
        )
    ]


def test_until_closes_the_window(publish: Door, home: Path, tmp_path: Path) -> None:
    since, until = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 4, 1, tzinfo=UTC)
    argv = ("--since", since.isoformat(), "--until", until.isoformat(), "--out", str(tmp_path))
    rc, _ = run(home, "program", *argv)
    assert rc == 0
    [(_, scope)] = publish.calls
    assert scope.window == TimeWindow(start=since, end=until) and scope.as_of is None


def test_executive_summary_as_of_writes_its_files(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    publish.result = RenderedView(
        view=ViewName.EXECUTIVE_SUMMARY,
        stem="executive-summary-findings",
        model=insight.ExecutiveSummary(
            rollup=insight.FindingsRollup(as_of=AS_OF, total=insight.FindingTally()),
            privileges=insight.LeastPrivilege(
                profiles=0,
                privileged=0,
                scc_requesting=0,
                wildcard_repositories=0,
                wildcard_rules=0,
            ),
        ),
        markdown="# Executive summary: findings\n",
        html="<!doctype html><title>Executive summary: findings</title>",
    )
    out = tmp_path / "dashboards"
    rc, answer = run(home, "executive-summary", "--as-of", AS_OF.isoformat(), "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=AS_OF))]
    assert sorted(p.name for p in out.iterdir()) == [
        "executive-summary-findings.html",
        "executive-summary-findings.json",
        "executive-summary-findings.md",
    ]
    assert answer["model"]["exposure"] is None


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (("--product", "gamma"), "product gamma is not registered"),
        (("--as-of", "2026-09-01T00:00:00"), "time zone"),
        (("--since", "2026-01-01"), "time zone"),
    ],
)
def test_a_refused_request_is_exit_2_and_writes_nothing(
    publish: Door, home: Path, tmp_path: Path, argv: tuple[str, ...], reason: str
) -> None:
    out = tmp_path / "out"
    rc, err = run(home, "findings-trend", *argv, "--out", str(out))
    assert rc == 2 and reason in err
    assert publish.calls == [] and not out.exists()


def test_a_door_refusal_is_exit_2(publish: Door, home: Path, tmp_path: Path) -> None:
    publish.result = ValidationError("the program view needs a window")
    rc, err = run(home, "program", "--out", str(tmp_path / "out"))
    assert rc == 2 and "needs a window" in err
    assert not (tmp_path / "out").exists()


def test_an_unknown_view_is_a_usage_error(publish: Door, home: Path, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()):
        dashboard_view.main(["--config-home", str(home), "nope", "--out", str(tmp_path)])
    assert exit.value.code == 2 and publish.calls == []


@pytest.fixture
def policies(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """The SLA policy each `services()` call saw registered on its Context."""
    seen: list[Any] = []
    services = SimpleNamespace(insight=SimpleNamespace(publish=Door(RENDERED)))

    def build(self: Context) -> SimpleNamespace:
        seen.append(self.sla_policy or self.default_sla_policy)
        return services

    monkeypatch.setattr(Context, "services", build)
    return seen


def test_the_packs_sla_policy_is_the_default_not_the_config_homes(
    policies: list[Any], home: Path, tmp_path: Path
) -> None:
    (home / "sla-policy.yaml").write_text(SLA_POLICY.read_text().replace("fedramp-rev5-", "home-"))
    rc, _ = run(home, "sla", "--out", str(tmp_path / "sla"))
    assert rc == 0
    assert [p.policy_name for p in policies] == ["fedramp-rev5-ra-5"]


def test_sla_policy_flag_wins_over_the_default(
    policies: list[Any], home: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.yaml"
    other.write_text(SLA_POLICY.read_text().replace("fedramp-rev5-ra-5", "fedramp"))
    assert run(home, "sla", "--sla-policy", str(other), "--out", str(tmp_path))[0] == 0
    assert run(home, "findings-trend", "--out", str(tmp_path))[0] == 0
    assert [p.policy_name for p in policies] == ["fedramp", "fedramp-rev5-ra-5"]


@pytest.mark.parametrize("policy", ["missing.yaml", "invalid.yaml"])
def test_an_unresolvable_sla_policy_is_exit_2_and_writes_nothing(
    policies: list[Any], home: Path, tmp_path: Path, policy: str
) -> None:
    (tmp_path / "invalid.yaml").write_text("policy_name: x\n")
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()) as err:
        argv = ["sla", "--sla-policy", str(tmp_path / policy), "--out", str(out)]
        dashboard_view.main(["--config-home", str(home), *argv])
    assert exit.value.code == 2 and "SLA policy not resolvable" in err.getvalue()
    assert policies == [] and not out.exists()


def test_threat_register_writes_its_files(publish: Door, home: Path, tmp_path: Path) -> None:
    publish.result = RenderedView(
        view=ViewName.THREAT_REGISTER,
        stem="threat-register",
        model=insight.ThreatRegister(as_of=AS_OF, repository_urls={}, models=0),
        markdown="# Threat register\n",
        html="<!doctype html><title>Threat register</title>",
    )
    out = tmp_path / "threat-register"
    argv = ("--product", "alpha", "--as-of", AS_OF.isoformat(), "--out", str(out))
    rc, answer = run(home, "threat-register", *argv)
    assert rc == 0
    assert publish.calls == [
        (ViewName.THREAT_REGISTER, ViewFilter(product_ids=(ALPHA.id,), as_of=AS_OF))
    ]
    assert sorted(p.name for p in out.iterdir()) == [
        "threat-register.html",
        "threat-register.json",
        "threat-register.md",
    ]
    assert (answer["model"]["models"], answer["model"]["threats"]) == (0, [])


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
def test_threat_register_on_core_renders_an_empty_fleet(tmp_path: Path, database: str) -> None:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if database == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        out = tmp_path / "out"
        rc, answer = run(config, "threat-register", "--out", str(out))
    assert rc == 0, answer
    assert answer["model"]["threats"] == [] and answer["model"]["quick_wins"] == []
    assert "_No threat models recorded._" in (out / "threat-register.md").read_text()


def test_freshness_reads_the_engines_tools_and_the_feeds_registry(
    publish: Door, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feeds: list[tuple] = []

    def engine_core(config_home: Path | None, **kw: Any) -> Context:
        core = Context.from_file(config_home / "traust.yaml")  # type: ignore[operator]
        monkeypatch.setattr(core, "register_feeds", lambda *a: feeds.append(a))
        return core

    monkeypatch.setattr(dashboard_view, "load", engine_core)
    publish.result = RENDERED.model_copy(update={"view": ViewName.FRESHNESS, "stem": "freshness"})
    rc, answer = run(home, "freshness", "--out", str(tmp_path / "fresh"))
    assert rc == 0, answer
    assert feeds == [()]  # core's shipped registry
    assert publish.calls == [(ViewName.FRESHNESS, ViewFilter())]
    assert (tmp_path / "fresh" / "freshness.md").is_file()


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
def test_attack_coverage_on_core_renders_on_the_pinned_catalog(
    tmp_path: Path, database: str
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if database == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        out = tmp_path / "out"
        rc, answer = run(config, "attack-coverage", "--out", str(out))
    assert rc == 0, answer
    assert answer["model"]["attack_version"] == "19.1" and answer["model"]["techniques"] == []
    layer = json.loads((out / "attack-coverage.json").read_text())["navigator_layer"]
    assert layer["versions"]["layer"] == "4.5" and "MITRE" in layer["description"]


def test_an_unresolvable_attack_catalog_is_exit_2(
    publish: Door, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust import context

    monkeypatch.setattr(context, "ATTACK_TABLES", (tmp_path / "t.json", tmp_path / "m.json"))
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()) as err:
        dashboard_view.main(["--config-home", str(home), "attack-coverage", "--out", str(tmp_path)])
    assert exit.value.code == 2 and "ATT&CK catalog not resolvable" in err.getvalue()
    assert publish.calls == []


def test_artifact_id_names_the_document_a_single_item_view_renders(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    assessment = uuid.uuid4()
    document = {"assessment-results": {"uuid": str(uuid.uuid4()), "results": []}}
    publish.result = RenderedView(
        view=ViewName.OSCAL,
        stem="acme-compliance-assessment",
        model=insight.OscalAssessmentResults.model_validate(document),
        markdown="# acme compliance assessment\n",
        html="<title>acme compliance assessment</title>",
    )
    out = tmp_path / "oscal"
    rc, answer = run(home, "oscal", "--artifact-id", str(assessment), "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.OSCAL, ViewFilter(artifact_id=assessment))]
    assert json.loads((out / "acme-compliance-assessment.json").read_text()) == document
    assert answer["model"] == document


def test_container_view_preserves_the_full_report_stem_and_anchor(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    assessment_id, repository_id = uuid.uuid4(), uuid.uuid4()
    stem = "Widget.RHEL9-container-audit"
    publish.result = RenderedView(
        view=ViewName.CONTAINER_FINDINGS,
        stem=f"{stem}-findings-current",
        model=insight.ContainerFindings(
            repository_id=repository_id,
            repository_url="https://github.com/example/widget",
            report_stem=stem,
            image_repository="registry.example:5000/apps/widget",
            reports=(),
            findings=(),
            total=insight.FindingTally(),
        ),
        markdown="# Current container findings\n",
        html="<title>Current container findings</title>",
    )
    out = tmp_path / "reports"
    out.mkdir()
    code_report = out / "Widget.RHEL9-findings-current.json"
    code_report.write_text('{"code": true}')
    rc, answer = run(
        home,
        "container-findings",
        "--assessment-id",
        str(assessment_id),
        "--report-stem",
        stem,
        "--out",
        str(out),
    )
    assert rc == 0
    assert publish.calls == [
        (
            ViewName.CONTAINER_FINDINGS,
            ViewFilter(assessment_id=assessment_id, report_stem=stem),
        )
    ]
    assert {path.name for path in out.iterdir()} == {
        code_report.name,
        *(f"{stem}-findings-current.{ext}" for ext in ("json", "md", "html")),
    }
    assert json.loads(code_report.read_text()) == {"code": True}
    assert json.loads((out / f"{stem}-findings-current.json").read_text()) == answer["model"]


def test_executive_segment_options_publish_real_inventory_counts(
    home: Path,
    tmp_path: Path,
) -> None:
    from traust_core.v1.models.values import HttpsRepoUrl

    from traust.context import load

    inputs = tmp_path / "inputs"
    (inputs / "services").mkdir(parents=True)
    (inputs / "services/scope-repos.csv").write_text(
        "URL\nhttps://github.com/example-org/service.git\n"
    )
    core = load(home)
    core.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example-org/service", ("github.com",)), public=True
    )
    out = tmp_path / "executive"
    rc, answer = run(
        home,
        "executive-summary",
        "--by-segment",
        "--inputs-root",
        str(inputs),
        "--panel",
        "isolation",
        "--panel",
        "iac",
        "--out",
        str(out),
    )
    assert rc == 0
    model = json.loads((out / "executive-summary-findings.json").read_text())
    assert model["segments"]["rows"][0]["segment"] == "services"
    assert model["segments"]["rows"][0]["repositories"] == 1
    assert model["segments"]["rows"][0]["tally"]["open"]["high"] == 0
    assert model["isolation"]["reviews"] == []
    assert model["iac"]["assessments"] == 0
    assert answer["model"] == model


def test_executive_options_refuse_unrelated_views_before_loading_or_writing(
    home: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "refused"
    with pytest.raises(SystemExit) as error:
        dashboard_view.main(
            [
                "--config-home",
                str(home),
                "findings-trend",
                "--panel",
                "attack",
                "--out",
                str(out),
            ]
        )
    assert error.value.code == 2
    assert not out.exists()


def test_loc_comparison_and_calibration_options_reach_core(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    from decimal import Decimal

    earlier = datetime(2026, 9, 1, tzinfo=UTC)
    rc, answer = run(
        home,
        "loc",
        "--compare-as-of",
        earlier.isoformat(),
        "--first-party-divisor",
        "1.6",
        "--out",
        str(tmp_path / "loc"),
    )
    assert rc == 0, answer
    assert publish.calls == [
        (ViewName.LOC, ViewFilter(compare_as_of=earlier, first_party_divisor=Decimal("1.6")))
    ]


def test_spend_repricing_and_workstation_options_reach_core(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    rc, answer = run(
        home, "spend", "--reprice", "--workstation-spend", "--out", str(tmp_path / "spend")
    )
    assert rc == 0, answer
    assert publish.calls == [
        (ViewName.SPEND, ViewFilter(reprice_spend=True, workstation_spend=True))
    ]


@pytest.mark.parametrize(
    "options",
    [
        ("--compare-as-of", AS_OF.isoformat()),
        ("--first-party-divisor", "1.6"),
        ("--reprice",),
        ("--workstation-spend",),
    ],
)
def test_view_specific_options_cannot_silently_change_another_view(
    publish: Door, home: Path, tmp_path: Path, options: tuple[str, ...]
) -> None:
    out = tmp_path / "wrong-view"
    rc, _ = run(home, "scoreboard", *options, "--out", str(out))
    assert rc == 2
    assert publish.calls == []
    assert not out.exists()


@pytest.mark.parametrize("divisor", ["0", "-1", "NaN", "Infinity"])
def test_invalid_loc_divisor_is_rejected_before_publication(
    publish: Door, home: Path, tmp_path: Path, divisor: str
) -> None:
    out = tmp_path / "invalid-divisor"
    rc, _ = run(home, "loc", "--first-party-divisor", divisor, "--out", str(out))
    assert rc == 2
    assert publish.calls == []
    assert not out.exists()
