"""mutation_evidence.py — verdicts derived from real mewt 4.0.0 output.

The two status fixtures are captured from actual campaigns against a Go module
with a deliberately weak test (2026-09-16), not hand-written. An earlier
version of this tool scraped the campaign banner for "killed/survived", words
mewt does not print — it prints Caught/Uncaught/Skipped — so it would have
returned no verdict on every real run. These tests exist so the parser is
pinned to the shape the tool actually emits.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "mutation_evidence",
    skill_dir("remediate-finding") / "scripts" / "mutation_evidence.py",
)
me = importlib.util.module_from_spec(_SPEC)
sys.modules["mutation_evidence"] = me
_SPEC.loader.exec_module(me)

FIXTURES = Path(__file__).parent / "fixtures" / "mutation"


def _item(fixture: str, rc: int = 0, target: str = "./pkg/calc"):
    return me.build_item(
        target=target,
        rc=rc,
        tool_version="mewt 4.0.0",
        log_path="/tmp/campaign.log",
        status_text=(FIXTURES / fixture).read_text() if fixture else None,
    )


def test_uncaught_mutant_fails_to_prove():
    """Real campaign: 2 uncaught in the source file, so the tests miss changes."""
    item = _item("status-uncaught.json")
    assert item["outcome"] == "fails_to_prove"
    assert "2 uncaught" in item["patched_observation"]


def test_all_caught_and_none_skipped_proves():
    """Real campaign after strengthening the test: 19/19 caught, 0 skipped."""
    item = _item("status-all-caught.json", target="./pkg/calc/calc.go")
    assert item["outcome"] == "proves"
    assert "19 caught, 0 uncaught" in item["patched_observation"]


def test_proof_claims_carry_both_observations():
    """The schema requires it; assert the producer never emits a bare claim."""
    for fixture in ("status-uncaught.json", "status-all-caught.json"):
        item = _item(fixture)
        assert item["base_observation"] and item["patched_observation"]


def test_test_file_mutants_are_excluded_from_the_claim():
    """A dead assertion inside a _test.go file is a different question."""
    item = _item("status-uncaught.json")
    assert "test-file target(s) excluded" in item["base_observation"]
    # the source file had 19 generated; the test file's 6 must not be folded in
    assert item["base_observation"].startswith("19 mutant(s)")


def test_unexercised_mutants_block_a_proof_claim():
    """mewt skips less severe mutants on a line whose severe mutant escaped.

    Zero uncaught with a non-zero skip count is not proof — it is a campaign
    that stopped short, and rounding it up would overclaim the one thing this
    evidence kind is for.
    """
    status = json.dumps(
        {
            "targets": [
                {
                    "path": "./pkg/x/x.go",
                    "total_mutants": 10,
                    "tested": 4,
                    "untested": 0,
                    "caught": 4,
                    "uncaught": 0,
                    "timeout": 0,
                    "skipped": 6,
                }
            ]
        }
    )
    item = me.build_item(
        target="./pkg/x", rc=0, tool_version="mewt 4.0.0", log_path="l", status_text=status
    )
    assert item["outcome"] == "fails_to_prove"
    assert "not every mutant was run" in item["patched_observation"]


def test_timed_out_mutants_block_a_proof_claim():
    status = json.dumps(
        {
            "targets": [
                {
                    "path": "./pkg/x/x.go",
                    "total_mutants": 5,
                    "tested": 5,
                    "untested": 0,
                    "caught": 4,
                    "uncaught": 0,
                    "timeout": 1,
                    "skipped": 0,
                }
            ]
        }
    )
    item = me.build_item(
        target="./pkg/x", rc=0, tool_version="mewt 4.0.0", log_path="l", status_text=status
    )
    assert item["outcome"] == "fails_to_prove"


def test_timeout_exit_is_not_attempted():
    item = _item("status-all-caught.json", rc=124)
    assert item["outcome"] == "not_attempted: campaign exceeded its timeout"
    assert item["deterministic_steps"] == "skipped: timeout"


def test_missing_status_is_not_attempted_not_a_verdict():
    item = _item("", rc=1)
    assert item["outcome"].startswith("not_attempted:")
    assert "base_observation" not in item


def test_unparseable_status_is_not_attempted():
    item = me.build_item(
        target="./p", rc=0, tool_version="", log_path="l", status_text="not json at all"
    )
    assert item["outcome"] == "not_attempted: mewt status json was unparseable"


def test_no_source_targets_is_not_attempted():
    status = json.dumps({"targets": [{"path": "./p/p_test.go", "total_mutants": 3}]})
    item = me.build_item(target="./p", rc=0, tool_version="", log_path="l", status_text=status)
    assert item["outcome"].startswith("not_attempted: mewt generated no mutants")


@pytest.mark.parametrize(
    "version,expected",
    [("mewt 4.0.0", "mewt 4.0.0"), ("4.0.0", "mewt 4.0.0"), ("", "mewt")],
)
def test_tool_label_is_not_double_prefixed(version, expected):
    assert me._tool_label(version) == expected


def test_boundary_is_recorded_in_the_command():
    """A verdict from nested podman and one from an attested sandbox are not
    equally strong; the artifact has to say which produced it."""
    for boundary in ("podman", "attested:konflux-job"):
        item = me.build_item(
            target="./pkg/x",
            rc=0,
            tool_version="mewt 4.0.0",
            log_path="l",
            status_text=(FIXTURES / "status-all-caught.json").read_text(),
            boundary=boundary,
        )
        assert f"[boundary: {boundary}]" in item["command"]


def test_boundary_is_optional():
    item = _item("status-all-caught.json", target="./pkg/calc/calc.go")
    assert "[boundary:" not in item["command"]
