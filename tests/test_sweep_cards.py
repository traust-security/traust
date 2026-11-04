"""`traust sweep cards`: the CLI layer only. Parsing is traust-core's `CardDeck`; the sweep is one
`DetectionQualityService.sweep_cards`, stubbed here. Exit 1 on an unpinned reject, 2 on a refusal."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.detection_quality import (
    CardEnumerator,
    CardRun,
    CardStatus,
    CardSweep,
    PrecedentCard,
)

from traust.cli import precedent_cards
from traust.paths import skill_dir

PILOT = skill_dir("mine-ledger") / "precedent-cards" / "pilot.yaml"
VALID = [
    "pc-unguarded-route-class",
    "pc-dsn-plaintext-default",
    "pc-anon-bindall-listener-default",
    "pc-sanitizer-bypass-survivor",
]


class Sweep:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], ToolRequest]] = []

    def __call__(self, cards: tuple[PrecedentCard, ...], request: ToolRequest) -> CardSweep:
        self.calls.append(([c.id for c in cards], request))
        return CardSweep(
            repo=request.workspace.name,
            cards=tuple(
                CardRun(
                    id=c.id, enumerator=CardEnumerator(c.enumerator), status=CardStatus.COMPILED
                )
                for c in cards
            ),
        )


@pytest.fixture
def door(monkeypatch: pytest.MonkeyPatch) -> Sweep:
    sweep = Sweep()
    services = SimpleNamespace(detection_quality=SimpleNamespace(sweep_cards=sweep))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return sweep


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(home: Path, *argv: object) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = precedent_cards.main(["--config-home", str(home), *map(str, argv)])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_validating_the_pilot_sweeps_nothing(door: Sweep, home: Path) -> None:
    rc, out = call(home, PILOT)
    assert rc == 0
    assert out["valid"] == VALID
    assert [r["id"] for r in out["rejected"]] == ["pc-REJECT-oauth-callback-prose"]
    assert "candidates" not in out and door.calls == []


def test_a_checkout_sweeps_the_valid_cards(door: Sweep, home: Path, tmp_path: Path) -> None:
    rc, out = call(home, PILOT, "--checkout", tmp_path / "svc")
    assert rc == 0
    [(ids, request)] = door.calls
    assert ids == VALID and request.workspace == (tmp_path / "svc").resolve()
    assert out["repo"] == "svc" and out["candidates"] == []
    assert len(out["rejected"]) == 1


def test_one_card_and_a_written_result(door: Sweep, home: Path, tmp_path: Path) -> None:
    target = tmp_path / "out" / "cards.json"
    rc, out = call(
        home, PILOT, "--checkout", tmp_path, "--card", "pc-dsn-plaintext-default", "--out", target
    )
    assert (rc, out) == (0, {"wrote": str(target), "candidates": 0})
    assert door.calls[0][0] == ["pc-dsn-plaintext-default"]
    assert json.loads(target.read_text())["rejected"] == []


def test_an_unpinned_reject_is_exit_1(door: Sweep, home: Path, tmp_path: Path) -> None:
    cards = tmp_path / "cards.yaml"
    cards.write_text(yaml.safe_dump({"cards": [{"id": "pc-prose", "checklist": ["look"]}]}))
    rc, out = call(home, cards)
    assert rc == 1
    assert "prose_checklist_fields" in " ".join(out["rejected"][0]["reasons"])


@pytest.mark.parametrize(
    ("document", "argv", "reason"),
    [
        ({"card": []}, (), "cards:"),
        ({"cards": []}, ("--card", "pc-missing"), "no card 'pc-missing'"),
    ],
)
def test_a_refused_file_is_exit_2(
    door: Sweep, home: Path, tmp_path: Path, document: dict, argv: tuple, reason: str
) -> None:
    cards = tmp_path / "cards.yaml"
    cards.write_text(yaml.safe_dump(document))
    rc, err = call(home, cards, *argv)
    assert rc == 2 and reason in err


def test_a_missing_file_is_exit_2(door: Sweep, home: Path, tmp_path: Path) -> None:
    rc, err = call(home, tmp_path / "absent.yaml")
    assert rc == 2 and "absent.yaml" in err
