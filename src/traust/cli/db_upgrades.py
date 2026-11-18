#!/usr/bin/env python3
"""The db-contract upgrade channel, on the operator's command.

``traust db upgrades`` plans: what the store has not run - names, hashes,
declared destructive reasons - and touches nothing. ``--apply`` runs the
plan, the operator's explicit call; a script that declared a destructive
reason needs ``--allow-destructive`` with it, the acknowledgement the
surface demands after the refusal has named what would run and why.

Exit 0: current (or applied, or no store yet - an open creates it).
Exit 1: anything waiting on an operator - pending without ``--apply``,
version 0, a channel refusal.
"""

from __future__ import annotations

import sys

from traust_core.v1.context import StoreState
from traust_core.v1.errors import ConfigError

from traust.cli._doors import parser
from traust.context import load


def _plan_line(upgrade) -> str:
    mark = f"  [destructive: {upgrade.destructive}]" if upgrade.destructive else ""
    return f"  {upgrade.name}  sha256:{upgrade.sha256[:12]}{mark}"


def main(argv: list[str] | None = None) -> int:
    ap = parser("db", "upgrades", "Plan and apply the store's db-contract upgrades.")
    ap.add_argument(
        "--apply", action="store_true", help="apply what the plan shows (default: plan only)"
    )
    ap.add_argument(
        "--allow-destructive",
        action="store_true",
        help="with --apply: acknowledge scripts that declare a destructive reason",
    )
    args = ap.parse_args(argv)
    context = load(args.config_home)

    status = context.store_status()
    if status.state is StoreState.EMPTY:
        print("no store yet: it is created on first open (local) or by its deployment")
        return 0
    if status.state is StoreState.VERSION_0:
        print(
            "version 0: the store predates the upgrade channel - adopt (planned) or "
            "recreate it (core README, Store upgrades)"
        )
        return 1

    if not status.pending:
        print("up to date")
        return 0

    print(f"{len(status.pending)} upgrade(s) pending:")
    for upgrade in status.pending:
        print(_plan_line(upgrade))

    if not args.apply:
        print("pending upgrades - rerun with --apply to run them")
        return 1

    try:
        applied = context.apply_db_upgrades(allow_destructive=args.allow_destructive)
    except ConfigError as error:
        print(str(error), file=sys.stderr)
        return 1
    names = ", ".join(upgrade.name for upgrade in applied) or "nothing"
    print(f"applied {len(applied)} upgrade(s): {names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
