"""`traust sweep mine`: the CLI layer only. A rule pack from traust-engine's RulePackSource (by
name), then one `DetectionQualityService.mine_rules`; a refused input is exit 2. Mining itself is
traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.detection_quality import RuleMining, RulePack, RuleRef

from traust.cli.groups import sweep

TRAUST = RulePack(
    name="traust",
    version="0.38.0",
    rules=(RuleRef(id="py-sqli", languages=("python",), cwes=("CWE-89",)),),
)
ARGUS = RulePack(name="argus", version="pin", rules=())


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[Any] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result(*args) if callable(self.result) else self.result


@pytest.fixture
def quality(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        rule_packs=Door([TRAUST, ARGUS]), mine_rules=Door(lambda p: RuleMining(pack=p))
    )
    core = SimpleNamespace(services=lambda: SimpleNamespace(detection_quality=stub))
    monkeypatch.setattr(sweep, "load_engine_core", lambda home: core)
    return stub


def call(**args: Any) -> tuple[int, Any]:
    ns = SimpleNamespace(**{"config_home": None, "pack": "traust", "out": None, **args})
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sweep.call_mine(None, ns)
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_the_traust_pack_is_mined_by_default(quality: SimpleNamespace) -> None:
    rc, out = call()
    assert rc == 0
    assert quality.mine_rules.calls == [(TRAUST,)]
    assert (out["pack"], out["pack_rules"], out["confirmed_tps"]) == ("traust 0.38.0", 1, 0)
    assert out["uncovered"] == [] and "corpus" not in out


def test_a_supplement_is_chosen_by_name(quality: SimpleNamespace) -> None:
    rc, _ = call(pack="argus")
    assert rc == 0 and quality.mine_rules.calls == [(ARGUS,)]


def test_out_also_writes_the_whole_mining(quality: SimpleNamespace, tmp_path: Path) -> None:
    target = tmp_path / "metrics" / "rule-mining.json"
    rc, _ = call(out=target)
    assert rc == 0
    assert RuleMining.model_validate_json(target.read_text()) == RuleMining(pack=TRAUST)


def test_an_unknown_pack_is_exit_2(quality: SimpleNamespace) -> None:
    rc, err = call(pack="nope")
    assert rc == 2 and "'nope'" in err and "argus" in err
    assert quality.mine_rules.calls == []


@pytest.mark.parametrize("door", ["rule_packs", "mine_rules"])
def test_a_refusing_door_is_exit_2(quality: SimpleNamespace, door: str) -> None:
    getattr(quality, door).result = ConfigError("refused")
    rc, err = call()
    assert rc == 2 and "refused" in err
