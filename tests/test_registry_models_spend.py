"""`traust registry models spend`: a skill's end-of-run declaration recorded as a core spend
event (`SpendService.record`), on SQLite and Postgres."""

from __future__ import annotations

import contextlib
import io
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import SpendDimension, SpendEvent, SpendFilter
from traust_core.v1.services.operations import SpendService

from tests.test_products_doors import _postgres
from traust.cli.__main__ import main as cli
from traust.context import load

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
HAIKU = "      claude-haiku-5-5:"
UNPRICED = "      claude-unpriced-x:      {tier: haiku-class, batch_eligible: true}\n"


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    text = REGISTRY.read_text()
    (config / "model-registry.yaml").write_text(text.replace(HAIKU, UNPRICED + HAIKU, 1))
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[SpendEvent]:
    saved: list[SpendEvent] = []
    record = SpendService.record

    def spy(self: SpendService, event: SpendEvent) -> SpendEvent:
        saved.append(record(self, event))
        return saved[-1]

    monkeypatch.setattr(SpendService, "record", spy)
    return saved


def spend(home: Path, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli(["registry", "models", "--config-home", str(home), "spend", *argv])
    return rc, out.getvalue(), err.getvalue()


def by_model(home: Path) -> list[tuple[str | None, int, int, int, Decimal]]:
    window = TimeWindow(start=datetime(2000, 1, 1, tzinfo=UTC), end=datetime.now(UTC))
    rows = load(home).services().spend.summary(SpendFilter(window=window), SpendDimension.MODEL)
    return [(r.key, r.events, r.tokens_in, r.tokens_out, r.cost_usd) for r in rows]


@pytest.mark.parametrize(
    ("tokens_in", "tokens_out", "cache_read", "cost"),
    [
        # 1000 in at $0.1, 100 out at $0.5, 50 cache reads at 0.1x input (per MTok)
        (1000, 100, 50, "0.0001505"),
        # input plus cache reads over haiku's 100k threshold: every token at $0.5 / $2.5
        (95000, 700, 9000, "0.0497"),
        (0, 0, 0, "0"),
    ],
)
def test_a_declaration_records_one_priced_core_spend_event(
    home: Path,
    recorded: list[SpendEvent],
    tokens_in: int,
    tokens_out: int,
    cache_read: int,
    cost: str,
) -> None:
    before = datetime.now(UTC)
    tokens = ("--tokens-in", str(tokens_in), "--tokens-out", str(tokens_out))
    argv = ("--skill", "triage", "--model", "claude-haiku-5-5", *tokens)
    assert spend(home, *argv, "--cache-read", str(cache_read)) == (0, "", "")
    [event] = recorded
    assert event.model_dump(include={"provider", "model", "skill", "lane", "run_order_id"}) == {
        "provider": "anthropic",
        "model": "claude-haiku-5-5",
        "skill": "triage",
        "lane": None,
        "run_order_id": None,
    }
    assert (event.tokens_in, event.tokens_out, event.cost_usd) == (
        tokens_in,
        tokens_out,
        Decimal(cost),
    )
    assert before <= event.occurred_at <= datetime.now(UTC)
    assert by_model(home) == [("claude-haiku-5-5", 1, tokens_in, tokens_out, Decimal(cost))]


def test_each_declaration_is_another_event_as_each_journal_append_was(
    home: Path, recorded: list[SpendEvent]
) -> None:
    argv = ("--skill", "triage", "--model", "claude-haiku-5-5", "--tokens-out", "100")
    assert spend(home, *argv)[0] == spend(home, *argv)[0] == 0
    assert len({e.id for e in recorded}) == 2
    assert by_model(home) == [("claude-haiku-5-5", 2, 0, 200, Decimal("0.0001"))]


def test_the_skill_md_invocation_records_and_names_the_flags_not_stored(
    home: Path, recorded: list[SpendEvent]
) -> None:
    rc, out, err = spend(
        home,
        *("--skill", "secure-code-audit", "--model", "claude-opus-5-5"),
        *("--tokens-in", "10", "--tokens-out", "20", "--repo", "org/repo", "--loc", "1234"),
        *("--batch", "b-1", "--note", "rerun"),
    )
    assert (rc, out, len(recorded)) == (0, "", 1)
    assert err.splitlines() == [
        f"spend: --{flag} not stored: spend_event has no column for it"
        for flag in ("repo", "loc", "batch", "note")
    ]


@pytest.mark.parametrize(
    ("model", "message"),
    [
        ("claude-not-in-the-registry", "model 'claude-not-in-the-registry' is not in the model"),
        ("claude-unpriced-x", "model 'claude-unpriced-x' has no price in the model registry"),
    ],
)
def test_an_unknown_or_unpriced_model_exits_1_and_records_nothing(
    home: Path, recorded: list[SpendEvent], model: str, message: str
) -> None:
    rc, out, err = spend(home, "--skill", "triage", "--model", model, "--tokens-out", "5")
    assert (rc, out, recorded, by_model(home)) == (1, "", [], [])
    assert err.startswith("spend: ") and message in err


def test_without_a_model_registry_the_declaration_is_refused(
    home: Path,
    recorded: list[SpendEvent],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry is required (the fail-loud plan): no skip path, no env switch — the
    declaration refuses, naming the fix, and records nothing."""
    (home / "model-registry.yaml").unlink()
    monkeypatch.delenv("HARNESS_REQUIRE_SPEND_LEDGER", raising=False)
    code, out, err = spend(home, "--skill", "triage", "--model", "claude-haiku-5-5")
    assert (code, out, recorded) == (1, "", [])
    assert err == (
        "spend: no model-registry.yaml in the config home — copy config/model-registry.yaml "
        "there (spend pricing and the spend view need it)\n"
    )
    assert by_model(home) == []
