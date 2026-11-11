"""Explicit approval intent and native order transitions through the script and Makefile."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    AssetName,
    OrderFilter,
    OrderRequest,
    OrderState,
    RunOrder,
)

from tests.local_ops_support import LocalOpsRig
from traust.context import load, load_caller


@pytest.fixture
def rig(tmp_path: Path) -> LocalOpsRig:
    fixture = LocalOpsRig(tmp_path)
    fixture.env.pop("ORDER", None)
    fixture.config_home.mkdir(parents=True)
    (fixture.config_home / "traust.yaml").write_text(
        yaml.safe_dump({"home": str(tmp_path / "store"), "identity": {"trust_local": True}})
    )
    signed_in = subprocess.run(
        [
            sys.executable,
            "-m",
            "traust.cli",
            "auth",
            "local",
            "--config-home",
            str(fixture.config_home),
            "--identity",
            "operator@example.test",
        ],
        cwd=fixture.root,
        env=fixture.env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert signed_in.returncode == 0, signed_in.stdout + signed_in.stderr
    core = load(fixture.config_home)
    caller = load_caller(core)
    ops = core.services().ops
    for asset in ("audit-one", "audit-two"):
        order = ops.plan(OrderRequest(asset=AssetName(asset), priority=1), caller)
        assert order.id is not None
        ops.request_approval(order.id)
    return fixture


def orders(rig: LocalOpsRig) -> list[RunOrder]:
    ops = load(rig.config_home).services().ops
    selected = OrderFilter(states=(OrderState.AWAITING_APPROVAL, OrderState.QUEUED))
    return list(every_item(lambda page: ops.list(selected, page)))


def states(rig: LocalOpsRig) -> dict[str, OrderState]:
    return {order.asset: order.state for order in orders(rig)}


@pytest.mark.parametrize("arguments", [(), ("",), (" ",), ("--all", "extra")])
def test_missing_blank_or_extra_script_arguments_leave_all_orders_awaiting(
    rig: LocalOpsRig, arguments: tuple[str, ...]
) -> None:
    before = states(rig)
    result = rig.run("approve", *arguments)
    assert result.returncode == 2, result.stdout + result.stderr
    assert states(rig) == before


@pytest.mark.parametrize("selector", [None, "", " "])
def test_make_never_treats_an_unset_or_blank_order_as_approve_all(
    rig: LocalOpsRig, selector: str | None
) -> None:
    before = states(rig)
    arguments = () if selector is None else (f"ORDER={selector}",)
    result = rig.make("ops-approve", *arguments)
    assert result.returncode != 0, result.stdout + result.stderr
    assert states(rig) == before


@pytest.mark.parametrize(
    "template",
    [
        "'; touch {marker}; #",
        'x"; bash scripts/local_ops.sh approve --all; #',
        "$(touch {marker})",
        "$(shell touch {marker})",
        "ORD-1; touch {marker}",
        "ORD *",
    ],
)
def test_shell_breaking_make_selectors_cannot_execute_or_approve(
    rig: LocalOpsRig, template: str
) -> None:
    marker = rig.root / "injected-command"
    selector = template.format(marker=marker)
    before = states(rig)
    result = rig.make("ops-approve", f"ORDER={selector}")
    assert result.returncode != 0, result.stdout + result.stderr
    assert not marker.exists()
    assert states(rig) == before


def test_make_approves_only_the_explicit_order(rig: LocalOpsRig) -> None:
    chosen, other = orders(rig)
    result = rig.make("ops-approve", f"ORDER={chosen.id}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert states(rig) == {
        chosen.asset: OrderState.QUEUED,
        other.asset: OrderState.AWAITING_APPROVAL,
    }


def test_bulk_approval_requires_the_explicit_make_target(rig: LocalOpsRig) -> None:
    result = rig.make("ops-approve-all")
    assert result.returncode == 0, result.stdout + result.stderr
    assert states(rig) == {"audit-one": OrderState.QUEUED, "audit-two": OrderState.QUEUED}
