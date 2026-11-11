"""The prepare and plan doors call core services with explicit input only."""

from __future__ import annotations

import json
from uuid import UUID

# Reused: a recorded finding with a bound source assessment.
from tests.test_validation_record import recording  # noqa: F401
from traust.cli.__main__ import main
from traust.context import load


def _config(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    return config


def test_plan_door_publishes_an_immutable_plan_artifact(tmp_path, capsys):
    config = _config(tmp_path)
    document = tmp_path / "plan.json"
    document.write_text(
        json.dumps(
            {"target": "example", "scope_binding_mode": "explicit", "chains": [], "steps": []}
        )
    )
    assert (
        main(["validation", "plan", "--config-home", str(config), "--document", str(document)]) == 0
    )
    ref = json.loads(capsys.readouterr().out)
    assert ref["digest"]
    stored = load(config).services().validation.get_plan(UUID(ref["id"]))
    assert stored.target == "example"


def test_plan_door_refuses_a_malformed_plan(tmp_path, capsys):
    config = _config(tmp_path)
    document = tmp_path / "plan.json"
    document.write_text(json.dumps({"scope_binding_mode": "explicit"}))
    assert (
        main(["validation", "plan", "--config-home", str(config), "--document", str(document)]) == 2
    )
    assert "ERROR" in capsys.readouterr().err


def test_prepare_door_hands_over_the_recorded_finding(recording, capsys):  # noqa: F811
    config = recording["config"]
    finding_id = recording["finding_id"]
    code = main(
        ["validation", "prepare", "--config-home", str(config), "--finding-id", str(finding_id)]
    )
    assert code == 0
    prepared = json.loads(capsys.readouterr().out)
    assert isinstance(prepared, list) and len(prepared) == 1


def test_prepare_door_refuses_an_unknown_finding(tmp_path, capsys):
    config = _config(tmp_path)
    load(config).services()  # materialize the store
    code = main(
        ["validation", "prepare", "--config-home", str(config), "--finding-id", str(UUID(int=0))]
    )
    assert code == 2
    assert "ERROR" in capsys.readouterr().err
