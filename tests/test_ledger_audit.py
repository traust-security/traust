"""`traust ledger audit`: the ledger_audit materializer. Core tests `LedgerService.audit` against
tampered layers; here, its outcome mapping and the door end to end on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import yaml
from traust_core.v1.models.ledger import VerifyResult
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason

from traust.cli import ledger_audit
from traust.ops.materializers import LedgerAuditMaterializer

TAMPERED = VerifyResult(layer_id=uuid4(), errors=("merkle_root mismatch",))
UNVERIFIED = VerifyResult(layer_id=uuid4(), warnings=("no public key configured",))
CLEAN = VerifyResult(layer_id=uuid4())


def audit(*results: VerifyResult) -> JobResult:
    ledger = SimpleNamespace(audit=lambda: list(results))
    materializer = LedgerAuditMaterializer(SimpleNamespace(ledger=ledger))  # type: ignore[arg-type]
    return materializer.materialize(AssetRequest(asset="ledger_audit", run_id="manual"))


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        ((), JobResult.succeeded()),
        ((CLEAN, CLEAN), JobResult.succeeded()),
        ((CLEAN, TAMPERED), JobResult.partly({"failed": 1})),
        ((UNVERIFIED, CLEAN), JobResult.partly({"unverified": 1})),
        (
            (TAMPERED, UNVERIFIED, VerifyResult(layer_id=uuid4(), errors=("x",), warnings=("y",))),
            JobResult.partly({"failed": 2, "unverified": 1}),
        ),
    ],
)
def test_a_layer_that_does_not_verify_is_never_green(
    results: tuple[VerifyResult, ...], expected: JobResult
) -> None:
    assert audit(*results) == expected


def test_no_ledger_configured_is_refused() -> None:
    materializer = LedgerAuditMaterializer(SimpleNamespace(ledger=None))  # type: ignore[arg-type]
    result = materializer.materialize(AssetRequest(asset="ledger_audit", run_id="manual"))
    assert (result.outcome, result.reason) == ("refused", OrderReason.LEDGER_UNCONFIGURED)


def run(home: Path) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = ledger_audit.main(["--config-home", str(home)])
    return rc, json.loads(out.getvalue())


@pytest.mark.parametrize(
    ("core", "expected"), [({"ledger": {}}, (0, "succeeded")), ({}, (5, "refused"))]
)
def test_the_door_end_to_end(tmp_path: Path, core: dict, expected: tuple[int, str]) -> None:
    home = tmp_path / "config"
    home.mkdir()
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store"), **core}))
    rc, result = run(home)
    assert (rc, result["outcome"]) == expected
