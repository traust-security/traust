"""``traust sweep cards``: mine-ledger's semantic precedent cards on traust-core.

Parses a card file (each rejected card with every reason); ``--checkout`` sweeps valid cards
over source, while ``--artifact`` replays supplied facts without running checkout tools.
Matched rows are triage candidates, never findings. Exit 1 on an unpinned rejection.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.code_facts import CodeFactsInput
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.detection_quality import CardDeck, CardFactInput

from traust.cli._doors import parser, run
from traust.context import load


def main(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "cards", "Validate precedent cards; sweep checkout or supplied facts.")
    ap.add_argument("cards", type=Path, help="YAML file with a top-level cards: list")
    ap.add_argument("--checkout", type=Path, help="sweep the valid cards over this checkout")
    ap.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="ENUMERATOR[:CARD]=JSON",
        help="replay pre-generated facts; never run checkout tools (repeatable)",
    )
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
        if args.checkout is not None or args.artifact:
            request = (
                ToolRequest(workspace=args.checkout.resolve())
                if args.checkout is not None
                else None
            )
            service = load(args.config_home).services().detection_quality
            if args.artifact:
                artifacts: list[CardFactInput] = []
                seen: set[tuple[str, str | None]] = set()
                for spec in args.artifact:
                    binding, equals, filename = spec.partition("=")
                    enumerator, colon, card_id = binding.partition(":")
                    if not equals or not filename or not enumerator or (colon and not card_id):
                        raise ValidationError(
                            f"bad --artifact {spec!r}: expected ENUMERATOR[:CARD]=JSON"
                        )
                    key = (enumerator, card_id if colon else None)
                    if key in seen:
                        raise ValidationError(f"duplicate --artifact binding {binding!r}")
                    seen.add(key)
                    artifacts.append(
                        CardFactInput(
                            enumerator=enumerator,
                            card_id=key[1],
                            facts=CodeFactsInput.model_validate_json(Path(filename).read_bytes()),
                        )
                    )
                sweep = service.sweep_cards(deck.cards, request, artifacts=tuple(artifacts))
            else:
                sweep = service.sweep_cards(deck.cards, request)
            result |= sweep.model_dump(mode="json")
        if args.out is None:
            return result
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return {"wrote": str(args.out), "candidates": len(result.get("candidates", []))}

    rc = run(call)
    return 1 if rc == 0 and unexpected else rc
