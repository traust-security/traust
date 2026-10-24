"""`traust remediation fleet-apply`: the CLI layer only. One door call on a Context carrying
traust-engine's applier; the run order the door checks (leased, for this repository) is the
caller's. The door and its guards are traust-core's tests, the applier traust-engine's."""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ForbiddenError, IntegrityError, ServiceError, ValidationError
from traust_core.v1.models.remediation import PatchResult

from tests.test_remediation_fleet import REPO, REPO_ID, Door, run
from traust.cli import remediation

FIX_ID, ORDER_ID, REF_ID, ASSESSMENT_ID = (uuid.uuid4() for _ in range(4))
PATCH = PatchResult(
    files_changed=(".tekton/push.yaml",),
    diff="--- a/.tekton/push.yaml\n+++ b/.tekton/push.yaml\n",
    fleet_fix_id=FIX_ID,
    repository_ref_id=REF_ID,
    assessment_id=ASSESSMENT_ID,
)
CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def applier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    stub = SimpleNamespace(apply=Door(PATCH), wired=[])

    def services(self: Context) -> SimpleNamespace:
        stub.wired.append(self.fleet_fix_applier is not None)
        return SimpleNamespace(
            remediation=SimpleNamespace(apply_fleet_fix=stub.apply),
            portfolio=SimpleNamespace(
                find_repository=lambda url: (
                    SimpleNamespace(id=REPO_ID) if str(url) == REPO else None
                )
            ),
        )

    monkeypatch.setattr(Context, "services", services)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return stub


@pytest.fixture
def engine_home(tmp_path: Path) -> Path:
    config = tmp_path / "engine-config"
    shutil.copytree(CONFIG, config)
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def apply(home: Path, *argv: str) -> tuple[int, Any]:
    return run(remediation.fleet_apply, home, str(FIX_ID), *argv)


def test_apply_is_one_door_call_through_the_engine_applier(
    applier: SimpleNamespace, engine_home: Path
) -> None:
    rc, out = apply(engine_home, "--repo-url", REPO, "--order", str(ORDER_ID))
    assert (rc, out) == (0, PATCH.model_dump(mode="json"))
    assert applier.apply.calls == [(FIX_ID, REPO_ID, ORDER_ID)]
    assert applier.wired and all(applier.wired)


def test_apply_writes_out(applier: SimpleNamespace, engine_home: Path, tmp_path: Path) -> None:
    out = tmp_path / "patch.json"
    argv = ("--repo-url", REPO, "--order", str(ORDER_ID), "-o", str(out))
    assert apply(engine_home, *argv) == (0, "")
    assert json.loads(out.read_text())["files_changed"] == [".tekton/push.yaml"]


@pytest.mark.parametrize(
    "argv",
    [
        ("--repo-url", REPO),
        ("--order", str(ORDER_ID)),
        ("--repo-url", REPO, "--order", "not-a-uuid"),
    ],
)
def test_apply_needs_a_repository_and_an_order(
    applier: SimpleNamespace, engine_home: Path, argv: tuple[str, ...]
) -> None:
    with pytest.raises(SystemExit):
        apply(engine_home, *argv)
    assert applier.apply.calls == []


def test_apply_unregistered_repository_is_exit_2(
    applier: SimpleNamespace, engine_home: Path
) -> None:
    rc, err = apply(
        engine_home, "--repo-url", "https://github.com/x/unknown", "--order", str(ORDER_ID)
    )
    assert rc == 2 and "not registered" in err
    assert applier.apply.calls == []


@pytest.mark.parametrize(
    "refusal",
    [
        ForbiddenError(f"run order {ORDER_ID} is not a leased order for repository {REPO_ID}"),
        IntegrityError("fleet fix konflux changed files outside its file_glob: ['README.md']"),
        ValidationError("guard: 9 files changed exceeds max_files_changed=5"),
        ServiceError("git clone failed"),
    ],
)
def test_apply_door_refusals_are_exit_2(
    applier: SimpleNamespace, engine_home: Path, refusal: Exception
) -> None:
    applier.apply.result = refusal
    rc, err = apply(engine_home, "--repo-url", REPO, "--order", str(ORDER_ID))
    assert rc == 2 and str(refusal) in err
