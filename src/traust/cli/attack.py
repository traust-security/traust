"""``traust attack validate``: check ATT&CK technique ids against the pack's pinned release."""

from __future__ import annotations

from traust_core.v1.errors import ValidationError

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("attack", "validate", "Check ATT&CK technique ids against the pinned release.")
    ap.add_argument("ids", nargs="+", help="technique ids (T1611, T1552.007)")
    args = ap.parse_args(argv)

    def call() -> str:
        catalog = load(args.config_home).attack_catalog
        assert catalog is not None  # load registers it or exits
        if invalid := catalog.invalid(args.ids):
            raise ValidationError("; ".join(invalid))
        return f"{len(args.ids)} technique ID(s) valid"

    return run(call)
