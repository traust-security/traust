"""302 legacy characterization cases; new Router parity awaits XWING-2215.

Run: uv run pytest -q tests/test_route_parity.py
See fixtures/routing/README.md for the provenance and remaining adapter work.
"""

import json
import socket
import subprocess
from pathlib import Path

import pytest

from tests.routing_reference import load_reference, run_primary, verify_digest

FIXTURES = Path(__file__).parent / "fixtures" / "routing"
BASELINE = json.loads((FIXTURES / "baseline.json").read_text(encoding="utf-8"))
DECISIONS = json.loads((FIXTURES / "python_decisions.json").read_text(encoding="utf-8"))
PRIMARY = json.loads((FIXTURES / "python_primary.json").read_text(encoding="utf-8"))
LEGACY_SOURCE = Path(__file__).resolve().parents[1] / DECISIONS["source"]["path"]


@pytest.fixture(scope="module")
def reference():
    return load_reference(LEGACY_SOURCE)


@pytest.fixture(scope="module", autouse=True)
def offline():
    def forbidden(*args, **kwargs):
        pytest.fail("routing parity must not use the network or spawn processes")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(socket.socket, "connect", forbidden)
        monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        monkeypatch.setattr(subprocess, "Popen", forbidden)
        yield


@pytest.mark.parametrize("filename", BASELINE["fixtures"])
def test_fixture_export_is_unchanged(filename):
    raw = (FIXTURES / filename).read_bytes()
    exported = BASELINE["fixtures"][filename]
    verify_digest(raw, exported["sha256"], filename)
    corpus = json.loads(raw)
    assert corpus["source"] == DECISIONS["source"]
    assert set(corpus) == {"source", *exported["counts"]}
    for group, count in exported["counts"].items():
        assert len(corpus[group]) == count, group
        names = [
            (case["source"], case["tier"]) if group == "event_lanes" else case["name"]
            for case in corpus[group]
        ]
        assert len(names) == len(set(names)), f"duplicate case IDs in {group}"


@pytest.mark.parametrize("case", DECISIONS["table"], ids=lambda case: case["name"])
def test_legacy_table(case, reference):
    namespace, _ = reference
    rule, lane, reason = namespace["decide"](case["input"].copy())
    assert {"Rule": rule, "Lane": lane, "Reason": reason} == case["want"]


@pytest.mark.parametrize("case", DECISIONS["risk"], ids=lambda case: case["name"])
def test_legacy_risk(case, reference):
    namespace, _ = reference
    risk = case["input"]
    assert (
        namespace["risk_tier"](risk["LiveCriticalHigh"], risk["Archived"], risk["Dormant"])
        == case["want"]
    )


@pytest.mark.parametrize(
    "case",
    PRIMARY["event_lanes"],
    ids=lambda case: f"{case['source'] or 'empty'}-{case['tier'] or 'unaudited'}",
)
def test_legacy_event_lane(case, reference):
    namespace, _ = reference
    assert namespace["event_lane"](case["source"], case["tier"] or None) == case["lane"]


@pytest.mark.parametrize("case", PRIMARY["primary"], ids=lambda case: case["name"])
def test_legacy_primary(case, reference, tmp_path):
    assert run_primary(*reference, case["input"], tmp_path) == case["want"]


def test_cases_detect_routing_behavior_drift(tmp_path):
    original = LEGACY_SOURCE.read_bytes()
    changed = original.replace(b"CHURN_FULL_LINES = 8000", b"CHURN_FULL_LINES = 9000", 1)
    assert changed != original
    # The 8000-line boundary case detects this behavior change directly:
    # the adapter executes current code, not a frozen copy or a source hash.
    source = tmp_path / "changed_worklist.py"
    source.write_bytes(changed)
    namespace, _ = load_reference(source)
    case = next(case for case in DECISIONS["table"] if case["name"] == "churn-lines-8000")
    rule, lane, reason = namespace["decide"](case["input"].copy())
    assert {"Rule": rule, "Lane": lane, "Reason": reason} != case["want"]


def test_guard_rejects_expected_output_drift():
    changed = json.loads((FIXTURES / "python_decisions.json").read_text(encoding="utf-8"))
    changed["table"][0]["want"]["Lane"] = "unreviewed-lane"
    with pytest.raises(ValueError, match="Review the fixture diff"):
        verify_digest(
            json.dumps(changed).encode(),
            BASELINE["fixtures"]["python_decisions.json"]["sha256"],
            "changed fixture",
        )
