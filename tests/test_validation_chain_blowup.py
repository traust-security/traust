"""Chain assembly must not re-explode.

Two filters in `build_validation_json` are load-bearing, and their
absence once produced a multi-gigabyte artifact: thousands of steps per
chain where a healthy chain carries a handful.

  GLUE steps are connectors, not path steps. The per-finding verdict
  logic already excludes them; chain assembly did not.
  DE-DUPLICATION by step_id. `results_by_fid` holds every result
  recorded for a finding, so each chain re-appended all of them — the
  cartesian product of chains x findings x results.

Both are one-line `continue`s and nothing would have caught either
being removed. That is what this file is for: the comment in report.py
was doing a test's job, and a comment cannot fail a build.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / "harnessing/5-validate/validate-findings"
sys.path.insert(0, str(SKILL))

import report as R


@dataclass
class _Result:
    finding_ref: str
    step_id: str
    verb: str = "get"
    verdict: str = "confirmed"
    novel_ref: str | None = None
    soundness_flag: str | None = None
    error: str | None = None


@dataclass
class _Chain:
    """The real Chain's fields that chain assembly reads."""

    chain_id: str = "C1"
    entry_point: str = "entry"
    terminal_asset: str = "asset"
    path: list = field(default_factory=list)
    finding_ids: list = field(default_factory=list)
    capabilities: list = field(default_factory=list)
    mitre: list = field(default_factory=list)
    name: str = ""
    narrative: str = ""


def _chain_steps(results, chain):
    """Run chain assembly and return the steps it produced."""
    doc = R.build_validation_json(
        _Normalized(), _Scope(), results, [chain], [],
        audit_path="a", audit_sha256="d", flags=[], approval={},
    )
    return doc["attack_chains"][0]["steps"]


@dataclass
class _Normalized:
    """The real Normalized, minus what chain assembly never touches."""

    target_name: str = "t"
    source_dir: str = "/tmp/t"
    source_reports: list = field(default_factory=list)
    findings: list = field(default_factory=list)


class _Scope:
    binding_mode = "explicit"
    engagement = None
    authorized_by = None
    expires = None

    def target_environment(self):
        return "lab-hub-1"


def test_glue_steps_never_enter_a_chain():
    """A connector is not a path step. Glue carried the bulk of the blowup."""
    results = [
        _Result("F1", "s1", verb="glue"),
        _Result("F1", "s2", verb="get"),
        _Result("F1", "s3", verb="glue"),
        _Result("F2", "s4", verb="get"),
        _Result("F2", "s5", verb="glue"),
    ]
    # two real steps, so the chain survives the len < 2 guard
    steps = _chain_steps(results, _Chain(finding_ids=["F1", "F2"]))
    assert [s["step_id"] for s in steps] == ["s2", "s4"]


def test_a_step_is_counted_once_per_chain():
    """results_by_fid holds every result for a finding; re-appending them
    per chain is the cartesian product that produced the rest of it."""
    results = [
        _Result("F1", "s1"),
        _Result("F1", "s1"),
        _Result("F1", "s1"),
        _Result("F2", "s2"),
    ]
    steps = _chain_steps(results, _Chain(finding_ids=["F1", "F2"]))
    assert [s["step_id"] for s in steps] == ["s1", "s2"]


def test_a_chain_stays_the_size_of_its_path():
    """The shape assertion: steps scale with the PATH, not with
    chains x findings x results. Without either filter this chain
    assembles 40 steps instead of 4."""
    results = []
    for fid in ("F1", "F2", "F3", "F4"):
        for repeat in range(5):          # the same result recorded 5x
            results.append(_Result(fid, f"{fid}-s1"))
            results.append(_Result(fid, f"{fid}-glue-{repeat}", verb="glue"))
    steps = _chain_steps(results, _Chain(finding_ids=["F1", "F2", "F3", "F4"]))
    assert len(steps) == 4, f"one step per finding on the path, got {len(steps)}"
