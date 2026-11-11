"""``traust sweep cards``: mine-ledger's semantic precedent cards on traust-core.

Parses a card file (each rejected card with every reason); with ``--checkout`` sweeps each valid
card's code-facts enumerator over the checkout and prints the matched rows as triage candidates
(the sweep-candidates shape /triage ingests), never findings. Exit 1 when a card is rejected that
isn't a pinned reject (``expect_reject``).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.detection_quality import CardDeck

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "cards", "Validate precedent cards; sweep them over a checkout.")
    ap.add_argument("cards", type=Path, help="YAML file with a top-level cards: list")
    ap.add_argument("--checkout", type=Path, help="sweep the valid cards over this checkout")
    ap.add_argument("--card", help="only this card id")
    ap.add_argument("--out", type=Path, help="also write the result here (JSON)")
    args = ap.parse_args(argv)
    unexpected = False

    def call() -> dict:
        nonlocal unexpected
        deck = CardDeck.parse(yaml.safe_load(args.cards.read_text(encoding="utf-8")))
        if args.card:
            deck = CardDeck(
                cards=tuple(c for c in deck.cards if c.id == args.card),
                rejected=tuple(r for r in deck.rejected if r.id == args.card),
            )
            if not deck.cards and not deck.rejected:
                raise NotFoundError(f"no card {args.card!r} in {args.cards}")
        unexpected = bool(deck.unexpected)
        result: dict = {
            "valid": [c.id for c in deck.cards],
            "rejected": [r.model_dump(mode="json") for r in deck.rejected],
        }
        if args.checkout is not None:
            request = ToolRequest(workspace=args.checkout.resolve())
            sweep = (
                load(args.config_home).services().detection_quality.sweep_cards(deck.cards, request)
            )
            result |= sweep.model_dump(mode="json")
        if args.out is None:
            return result
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return {"wrote": str(args.out), "candidates": len(result.get("candidates", []))}

    rc = run(call)
    return 1 if rc == 0 and unexpected else rc
