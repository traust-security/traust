"""`traust portfolio release-changes`: the CLI layer only. The product's recorded versions become
one `PortfolioService.release_changes` call (no previous: traust-core picks the high-water mark);
the answer is the change with `remodels`; a typed error is exit 2. The rule is traust-core's."""

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
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.inventory import Release, ReleaseBump, ReleaseChange

from traust.cli import portfolio_onboard

PRODUCT = SimpleNamespace(id=uuid.uuid4(), slug="openshift")
RELEASES = {v: Release(id=uuid.uuid4(), product_id=PRODUCT.id, version=v) for v in ("4.20", "4.21")}
ADDED = uuid.uuid4()


class Changes:
    def __init__(self, refusal: Exception | None = None) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.refusal = refusal

    def __call__(self, release_id: uuid.UUID, previous_id: uuid.UUID | None) -> ReleaseChange:
        self.calls.append((release_id, previous_id))
        if self.refusal is not None:
            raise self.refusal
        return ReleaseChange(
            release_id=release_id,
            previous_id=RELEASES["4.20"].id,
            version="4.21",
            previous_version="4.20",
            bump=ReleaseBump.MINOR,
            added=(ADDED,),
        )


def stub(monkeypatch: pytest.MonkeyPatch, door: Changes) -> Changes:
    portfolio = SimpleNamespace(
        find_product=lambda slug: {"openshift": PRODUCT}.get(str(slug)),
        find_release=lambda product_id, version: RELEASES.get(str(version)),
        release_changes=door,
    )
    monkeypatch.setattr(Context, "services", lambda self: SimpleNamespace(portfolio=portfolio))
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = portfolio_onboard.release_changes(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_a_version_against_its_high_water_mark(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    door = stub(monkeypatch, Changes())
    rc, out = run(home, "--product", "openshift", "--version", "4.21")
    assert rc == 0
    assert door.calls == [(RELEASES["4.21"].id, None)]
    assert (out["bump"], out["remodels"], out["added"]) == ("minor", True, [str(ADDED)])


def test_a_named_previous_version(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    door = stub(monkeypatch, Changes())
    rc, _ = run(home, "--product", "openshift", "--version", "4.21", "--previous", "4.20")
    assert rc == 0
    assert door.calls == [(RELEASES["4.21"].id, RELEASES["4.20"].id)]


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (("--product", "rhel", "--version", "4.21"), "product rhel is not registered"),
        (("--product", "openshift", "--version", "4.22"), "openshift 4.22 is not a recorded"),
        (("--product", "openshift", "--version", "4.21", "--previous", "4.1"), "openshift 4.1"),
    ],
)
def test_what_is_not_recorded_is_exit_2_before_any_comparison(
    monkeypatch: pytest.MonkeyPatch, home: Path, argv: tuple[str, ...], reason: str
) -> None:
    door = stub(monkeypatch, Changes())
    rc, err = run(home, *argv)
    assert rc == 2
    assert reason in err
    assert door.calls == []


def test_the_first_recorded_release_is_exit_2(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    stub(
        monkeypatch, Changes(NotFoundError("release 4.21 is its product's first recorded release"))
    )
    rc, err = run(home, "--product", "openshift", "--version", "4.21")
    assert rc == 2
    assert "first recorded release" in err
