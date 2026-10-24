"""`traust pqc …`: the CLI layer only. Arguments become one `PqcService` door call; a refused
input is exit 2. The doors themselves are traust-core's tests."""

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
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import PqcReadinessArtifact
from traust_core.v1.models.insight import (
    FindingsRollup,
    FindingTally,
    RenderedView,
    ViewFilter,
    ViewName,
)
from traust_core.v1.models.pqc import PqcDimension, PqcFilter
from traust_core.v1.models.vocabulary import PqcReadinessBucket, PqcRemediationCategory

from traust.cli import pqc

REPORT = Path(__file__).parent / "fixtures" / "pqc" / "widget-pqc-readiness.json"
URL = "https://github.com/acme/widget"
SHA = "f1b29843254b34f95ee1b36f1accca0380070962"
REF = uuid.uuid4()
PRODUCT = SimpleNamespace(id=uuid.uuid4(), slug="widget")
RENDERED = RenderedView(
    view=ViewName.PQC,
    stem="pqc",
    model=FindingsRollup(total=FindingTally()),
    markdown="# PQC readiness\n",
    html="<!doctype html><title>PQC readiness</title>",
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


class Dumps:
    def __init__(self, body: dict) -> None:
        self.body = body

    def model_dump_json(self, **_: Any) -> str:
        return json.dumps(self.body)

    def model_dump(self, **_: Any) -> dict:
        return self.body


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    repo = SimpleNamespace(id=uuid.uuid4())
    ref = SimpleNamespace(id=REF)
    stub = SimpleNamespace(
        record=Door(Dumps({"recorded": True})),
        check=Door(SimpleNamespace(violations=())),
        prepare=Door(Dumps({"route": "full"})),
        summary=Door([Dumps({"key": "partial"})]),
        blockers=Door([SimpleNamespace(model_dump=lambda **_: {"id": "R1"}, patchable=True)]),
        find_repository=Door(repo),
        find_ref=Door(ref),
        publish=Door(RENDERED),
    )
    services = SimpleNamespace(
        pqc=SimpleNamespace(
            record=stub.record,
            check=stub.check,
            prepare=stub.prepare,
            summary=stub.summary,
            blockers=stub.blockers,
        ),
        portfolio=SimpleNamespace(
            register_repository=lambda url, public: repo,
            register_ref=lambda *_: ref,
            find_repository=stub.find_repository,
            inventory=SimpleNamespace(find_ref=stub.find_ref),
            find_product=lambda slug: PRODUCT if str(slug) == "widget" else None,
        ),
        insight=SimpleNamespace(publish=stub.publish),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(op: str, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = getattr(pqc, op)(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_a_report_is_recorded_on_the_commit(doors: SimpleNamespace, home: Path) -> None:
    rc, out = call("record", home, "--repo-url", URL, "--sha", SHA, "--report", str(REPORT))
    assert (rc, out) == (0, {"recorded": True})
    ((ref_id, doc, source),) = doors.record.calls
    assert ref_id == REF and isinstance(doc, PqcReadinessArtifact)
    assert source.source == "interactive"


def test_facts_are_recorded_as_facts(
    doors: SimpleNamespace, home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    facts = tmp_path / "f.json"
    facts.write_bytes(b"{}")
    monkeypatch.setattr(pqc.PqcFactsArtifact, "parse", classmethod(lambda cls, raw: ("facts", raw)))
    rc, _ = call("record", home, "--repo-url", URL, "--sha", SHA, "--facts", str(facts))
    assert rc == 0
    assert doors.record.calls[0][1] == ("facts", b"{}")


def test_record_refused_by_the_gate_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.record.result = ValidationError("pqc-readiness report fails its gate")
    rc, err = call("record", home, "--repo-url", URL, "--sha", SHA, "--report", str(REPORT))
    assert rc == 2 and "fails its gate" in err


def test_record_needs_exactly_one_document(doors: SimpleNamespace, home: Path) -> None:
    with pytest.raises(SystemExit) as e:
        call("record", home, "--repo-url", URL, "--sha", SHA)
    assert e.value.code == 2
    assert not doors.record.calls


def test_check_passes_a_clean_report(doors: SimpleNamespace, home: Path) -> None:
    rc, out = call("check", home, str(REPORT))
    assert (rc, out) == (0, {"ok": True, "violations": []})
    assert isinstance(doors.check.calls[0][0], PqcReadinessArtifact)


def test_check_fails_a_report_with_violations(doors: SimpleNamespace, home: Path) -> None:
    violation = {"rule": "pqc-readiness", "item": "do_next", "message": "m", "action": "fix"}
    doors.check.result = SimpleNamespace(
        violations=(SimpleNamespace(model_dump=lambda **_: violation),)
    )
    rc, out = call("check", home, str(REPORT))
    assert (rc, out) == (1, {"ok": False, "violations": [violation]})


def test_check_refuses_a_report_that_fails_its_schema(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**json.loads(REPORT.read_text()), "readiness_bucket": "great"}))
    rc, err = call("check", home, str(bad))
    assert rc == 2 and "readiness_bucket" in err
    assert not doors.check.calls


def test_prepare_reads_the_registered_commit(doors: SimpleNamespace, home: Path) -> None:
    rc, out = call("prepare", home, "--repo-url", URL, "--sha", SHA)
    assert (rc, out) == (0, {"route": "full"})
    assert doors.prepare.calls == [(REF,)]
    assert doors.find_ref.calls[0][1] == SHA


def test_prepare_of_an_unknown_repository_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.find_repository.result = None
    rc, err = call("prepare", home, "--repo-url", URL, "--sha", SHA)
    assert rc == 2 and "not a registered repository" in err
    assert not doors.prepare.calls


def test_prepare_before_any_facts_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.prepare.result = NotFoundError("no pqc-facts; prescan it first")
    rc, err = call("prepare", home, "--repo-url", URL, "--sha", SHA)
    assert rc == 2 and "no pqc-facts" in err


def test_summary_defaults_to_buckets_over_everything(doors: SimpleNamespace, home: Path) -> None:
    rc, out = call("summary", home)
    assert (rc, out) == (0, [{"key": "partial"}])
    assert doors.summary.calls == [(PqcFilter(), PqcDimension.BUCKET)]


def test_summary_scopes_to_a_product_by_provenance(doors: SimpleNamespace, home: Path) -> None:
    rc, _ = call("summary", home, "--product", "widget", "--by", "provenance", "--bucket", "ready")
    assert rc == 0
    assert doors.summary.calls == [
        (
            PqcFilter(product_id=PRODUCT.id, buckets=(PqcReadinessBucket.READY,)),
            PqcDimension.PROVENANCE,
        )
    ]


def test_an_unknown_product_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = call("summary", home, "--product", "nope")
    assert rc == 2 and "nope" in err
    assert not doors.summary.calls


@pytest.mark.parametrize(
    ("flags", "categories", "patchable"),
    [
        ((), (), None),
        (("--patchable",), (), True),
        (("--not-patchable",), (), False),
        (
            ("--category", "fix-now", "--category", "deadline"),
            (PqcRemediationCategory.FIX_NOW, PqcRemediationCategory.DEADLINE),
            None,
        ),
    ],
)
def test_blockers_filter_by_category_and_anchoring(
    doors: SimpleNamespace,
    home: Path,
    flags: tuple[str, ...],
    categories: tuple[PqcRemediationCategory, ...],
    patchable: bool | None,
) -> None:
    rc, out = call("blockers", home, "--repo", URL, SHA, *flags)
    assert (rc, out) == (0, [{"id": "R1", "patchable": True}])
    assert doors.blockers.calls == [
        (PqcFilter(repository_ref_ids=(REF,), categories=categories, patchable=patchable),)
    ]


def test_blockers_take_one_anchoring_flag(doors: SimpleNamespace, home: Path) -> None:
    with pytest.raises(SystemExit) as e:
        call("blockers", home, "--patchable", "--not-patchable")
    assert e.value.code == 2
    assert not doors.blockers.calls


@pytest.mark.parametrize(
    ("flags", "products"), [((), ()), (("--product", "widget", "--product", "widget"), (1,))]
)
def test_dashboard_writes_the_pqc_view(
    doors: SimpleNamespace,
    home: Path,
    tmp_path: Path,
    flags: tuple[str, ...],
    products: tuple[int, ...],
) -> None:
    rc, out = call("dashboard", home, "--out", str(tmp_path / "d"), *flags)
    assert rc == 0
    product_ids = tuple(PRODUCT.id for _ in products)
    assert doors.publish.calls == [(ViewName.PQC, ViewFilter(product_ids=product_ids))]
    written = [Path(p) for p in out["written"]]
    assert [p.name for p in written] == [
        "pqc-dashboard.md",
        "pqc-dashboard.html",
        "pqc-dashboard.json",
    ]
    assert written[0].read_text() == "# PQC readiness\n"


def test_dashboard_of_an_unknown_product_writes_nothing(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    rc, err = call("dashboard", home, "--out", str(tmp_path / "d"), "--product", "nope")
    assert rc == 2 and "nope" in err
    assert not doors.publish.calls and not (tmp_path / "d").exists()
