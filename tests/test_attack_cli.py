"""`traust attack validate`: the CLI layer only; the rule is core's `AttackCatalog.invalid`."""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace

import pytest

from traust.cli import attack


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    seen: list[tuple[str, ...]] = []

    def invalid(ids: list[str]) -> tuple[str, ...]:
        seen.append(tuple(ids))
        return tuple(f"{i}: not in pinned ATT&CK table" for i in ids if i.startswith("T9"))

    core = SimpleNamespace(attack_catalog=SimpleNamespace(invalid=invalid))
    monkeypatch.setattr(attack, "load", lambda _home: core)
    return seen


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = attack.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def test_live_ids_pass(asked: list[tuple[str, ...]]) -> None:
    assert run("T1611", "T1552.007") == (0, "2 technique ID(s) valid\n", "")
    assert asked == [("T1611", "T1552.007")]


def test_any_bad_id_is_exit_2_naming_each(asked: list[tuple[str, ...]]) -> None:
    rc, out, err = run("T1611", "T9999", "T9998")
    assert (rc, out) == (2, "")
    assert "T9999: not in pinned ATT&CK table; T9998: not in pinned ATT&CK table" in err


def test_at_least_one_id_is_required(asked: list[tuple[str, ...]]) -> None:
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()):
        attack.main([])
    assert exit.value.code == 2 and asked == []
