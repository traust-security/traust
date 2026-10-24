"""property_evidence.py — the base-vs-patched verdict for property evidence.

Verified end to end on 2026-09-16 against a real Python fixture (a path
cleaner that stripped only one leading "../") with a real Hypothesis property:
containerised, the property failed on the base revision with the shrunk
counterexample `assert '..' not in ['..']` and passed on the patched one.

The case these tests exist to protect is the third row: a property that
passes on the UNPATCHED revision is not evidence about the fix, however true
it is. And the environmental rows — an exit code that did not come from a
test actually running must never become a verdict, which is how a sandbox
missing pluggy once produced a confident `fails_to_prove`.
"""

import importlib.util
import sys

import pytest

from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "property_evidence",
    skill_dir("property-test") / "scripts" / "property_evidence.py",
)
pe = importlib.util.module_from_spec(_SPEC)
sys.modules["property_evidence"] = pe
_SPEC.loader.exec_module(pe)


def _item(base_rc: int, patched_rc: int):
    return pe.build_item(
        test_path="tests/test_clean_property.py",
        base_ref="fa4b872",
        base_rc=base_rc,
        patched_rc=patched_rc,
        tool_version="hypothesis 6.168.0",
        base_log="/out/property-base.log",
        patched_log="/out/property-patched.log",
    )


def test_fails_on_base_and_passes_on_patch_proves():
    item = _item(1, 0)
    assert item["outcome"] == "proves"
    assert item["base_observation"] and item["patched_observation"]


def test_fails_on_both_is_an_incomplete_fix():
    item = _item(1, 1)
    assert item["outcome"] == "fails_to_prove"
    assert "still finds a counterexample" in item["patched_observation"]


def test_property_that_passed_before_the_patch_is_not_evidence():
    """The row people get wrong: true, but silent about this fix."""
    item = _item(0, 0)
    assert item["outcome"] == "fails_to_prove"
    assert "held before the patch" in item["patched_observation"]


def test_regression_introduced_by_the_patch_is_not_proof():
    item = _item(0, 1)
    assert item["outcome"] == "fails_to_prove"


@pytest.mark.parametrize("rc", [2, 3, 4])
def test_non_verdict_exit_codes_are_not_attempted(rc):
    """pytest exited without running tests — never a verdict."""
    for base, patched in ((rc, 0), (0, rc)):
        item = pe.build_item(
            test_path="t.py",
            base_ref="r",
            base_rc=base,
            patched_rc=patched,
            tool_version="",
            base_log="b",
            patched_log="p",
        )
        assert item["outcome"].startswith("not_attempted:"), (base, patched)
        assert "base_observation" not in item


def test_no_tests_collected_is_not_attempted():
    item = _item(5, 0)
    assert item["outcome"].startswith("not_attempted: pytest collected no tests")


def test_timeout_is_not_attempted():
    item = _item(124, 0)
    assert item["outcome"] == "not_attempted: property run exceeded its timeout"
    assert item["deterministic_steps"] == "skipped: timeout"


def test_a_proof_claim_always_carries_both_observations():
    """The schema enforces this; assert the producer cannot emit a bare claim."""
    item = _item(1, 0)
    assert item["base_observation"].startswith("on the unpatched revision")
    assert item["patched_observation"].startswith("on the patched revision")


def test_boundary_is_recorded_in_the_command():
    for boundary in ("podman", "attested:konflux-job"):
        item = pe.build_item(
            test_path="t.py",
            base_ref="r",
            base_rc=1,
            patched_rc=0,
            tool_version="hypothesis 6.168.0",
            base_log="b",
            patched_log="p",
            boundary=boundary,
        )
        assert f"[boundary: {boundary}]" in item["command"]


def test_boundary_is_optional():
    assert "[boundary:" not in _item(1, 0)["command"]
