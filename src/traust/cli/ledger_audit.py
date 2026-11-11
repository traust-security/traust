"""``traust ledger audit``: the `ledger_audit` asset's materializer, by hand or from a runner.
Verifies every ledger layer; prints the JobResult, whose outcome is the exit code."""

from __future__ import annotations

from traust_core.v1.models.operations import AssetRequest

from traust.cli._doors import answer, parser
from traust.context import load
from traust.ops.materializers import MANUAL, LedgerAuditMaterializer


def main(argv: list[str] | None = None) -> int:
    ap = parser("ledger", "audit", "Verify every ledger layer against its stored events.")
    ap.add_argument("--run-id", default=MANUAL, help="the run order this audit is for")
    args = ap.parse_args(argv)
    materializer = LedgerAuditMaterializer(load(args.config_home).services())
    return answer(
        materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
    )
