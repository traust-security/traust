"""`traust registry models` (list, resolve, validate, stamp) on traust-core's ModelCatalog, against
what traust-engine's `registry/models.py` printed for the fixture registry (captured before the
engine's copy was deleted). (The products parity went with the engine's `registry/products.py`,
deleted in traust-engine#113; core's product-definition tests own that behaviour.)
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from traust.cli.groups import registry

REGISTRY_SHA = hashlib.sha256(
    (Path(__file__).parent / "fixtures" / "config" / "model-registry.yaml").read_bytes()
).hexdigest()[:12]


def call(fn: Any, args: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(args)
    return rc, out.getvalue(), err.getvalue()


def models(cmd: str, **kw: Any) -> tuple[int, str, str]:
    return call(registry.call_models, SimpleNamespace(config_home=None, cmd=cmd, **kw))


def test_list_matches_the_engine() -> None:
    expected = [
        "deep-audit             floor=mythos-class  approved=claude-mythos-5",
        "fact-judge             floor=sonnet-class  approved=claude-sonnet-5,claude-opus-4-8,"
        "claude-mythos-5",
        "fuzz-author            floor=opus-class    approved=claude-opus-4-8,claude-mythos-5",
        "patch-author           floor=mythos-class  approved=claude-mythos-5",
        "patch-reviewer         floor=mythos-class  approved=claude-mythos-5",
        "remediation            floor=mythos-class  approved=claude-mythos-5",
        "render-narrate         floor=haiku-class   approved=claude-haiku-4-5-20251001,"
        "claude-sonnet-5,claude-opus-4-8",
        "threat-model           floor=mythos-class  approved=claude-mythos-5",
        "triage-verifier        floor=mythos-class  approved=claude-mythos-5",
        "validation-planner     floor=mythos-class  approved=claude-mythos-5",
        "verification-verdict   floor=mythos-class  approved=claude-mythos-5",
    ]
    assert models("list") == (0, "\n".join(expected) + "\n", "")


def test_validate_matches_the_engine() -> None:
    assert models("validate") == (0, "model registry: OK\n", "")


@pytest.mark.parametrize(
    ("role", "tier", "expected"),
    [
        ("fact-judge", None, "claude-sonnet-5"),
        ("fact-judge", "sonnet-class", "claude-sonnet-5"),
        ("fact-judge", "mythos-class", "claude-mythos-5"),
        ("deep-audit", None, "claude-mythos-5"),
    ],
)
def test_resolve_matches_the_engine(role: str, tier: str | None, expected: str) -> None:
    assert models("resolve", role=role, tier=tier) == (0, f"{expected}\n", "")


@pytest.mark.parametrize(
    ("role", "tier", "message"),
    [
        ("no-such-role", None, "unknown role 'no-such-role' — roles: ["),
        ("fact-judge", "nope-class", "unknown tier 'nope-class'"),
        ("deep-audit", "haiku-class", "tier-downs below the floor are never allowed"),
    ],
)
def test_an_unresolvable_role_exits_1_naming_why(role: str, tier: str | None, message: str) -> None:
    rc, out, err = models("resolve", role=role, tier=tier)
    assert (rc, out) == (1, "") and message in err


@pytest.mark.parametrize(
    ("role", "floor"), [("fact-judge", {"floor": "sonnet-class"}), ("no-such-role", {})]
)
def test_stamp_matches_the_engine(role: str, floor: dict[str, str]) -> None:
    expected = {"role": role, "model": "claude-x", "registry_sha": REGISTRY_SHA, **floor}
    assert models("stamp", role=role, model="claude-x") == (0, json.dumps(expected) + "\n", "")
