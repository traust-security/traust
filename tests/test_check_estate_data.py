#!/usr/bin/env python3
"""The estate-data gate: a measurement is a disclosure, a threshold is not.

The gate exists because a comma-grouped number in a public tree is
usually a statement about the deployment that produced it. The whole
difficulty is that three other things wear the same shape, and a gate
that cannot tell them apart is one people bypass:

  a regex quantifier      `{36,255}` — a bound, not a count
  a source-line reference `oauthproxy.go:525,685` — two LINE NUMBERS
  a configured threshold  `C >= 8,000` — what the policy DOES, not
                          what the estate IS

Each is stripped from the probe before the count rule runs. These tests
pin both directions: the three stay silent, and a real figure in prose
still trips even when it sits on the same line as one of them.

Every number below is invented. Using this deployment's real figures as
test data would republish exactly what the gate exists to keep out --
which is how the first draft of this file was written.
"""

from __future__ import annotations

import subprocess

import pytest

from traust.cli import check_estate_data as ced


def _hits(line: str) -> list[str]:
    probe = ced.QUANTIFIER_RE.sub("", line)
    probe = ced.SOURCE_LINE_REF_RE.sub("", probe)
    probe = ced.THRESHOLD_RE.sub("", probe)
    return ced.COUNT_RE.findall(probe)


class TestMeasurementsAreCaught:
    @pytest.mark.parametrize(
        "line",
        [
            "the ledger holds 4,321 confirmed and only 19 false_positive",
            "2026-07 was $111,111 workstation-wide",
            '"2,468 reports across 1,357 unique repositories"',
            "1,200 of 1,280 image tokens are bare keys",
            "# 404 fingerprints shared by 1,111 findings",
        ],
    )
    def test_a_figure_in_prose_trips(self, line):
        assert _hits(line), "a measured estate figure must be caught"


class TestLookalikesAreNot:
    @pytest.mark.parametrize(
        "line",
        [
            r'PATTERN = re.compile(r"[A-Za-z0-9]{36,255}")',
            "| **Location** | `oauthproxy.go:525,685` — HasPrefix misses |",
            "`login.go:127,157` and `logout.go:55`",
            "| 2 | `C >= 8,000` first-party changed lines |",
            "invalidates the baseline (C ≥ 8,000 first-party changed lines)",
        ],
    )
    def test_a_lookalike_stays_silent(self, line):
        assert not _hits(line), f"not a measurement: {line}"


class TestTheStripIsNotAWildcard:
    """Stripping must remove the lookalike, never the line around it."""

    def test_a_figure_beside_a_source_ref_still_trips(self):
        assert _hits("`api.go:92,125` — one of 1,234 findings") == ["1,234"]

    def test_a_figure_beside_a_threshold_still_trips(self):
        assert _hits("C >= 8,000 lines, measured over 5,678 reports") == ["5,678"]

    def test_a_lowercase_letter_is_not_a_threshold_symbol(self):
        # `x > 1,000` in prose is not the `C >= 8,000` policy shape; only a
        # bare capital reads as a declared threshold symbol.
        assert _hits("grew to > 1,000 findings") == ["1,000"]

    def test_an_assignment_is_not_a_threshold(self):
        # Bare `=` is excluded on purpose: hard-coding a figure into a
        # script is the most ordinary way one gets published.
        assert _hits("TOTAL = 1,234") == ["1,234"]


class TestWaiver:
    def test_a_cited_waiver_silences_the_line(self, tmp_path):
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        f = tmp_path / "a.py"
        f.write_text(
            "X = 1,234  # estate-data-ok: illustrative\nY = 1,235\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(tmp_path), "add", "a.py"], check=True)
        found = ced.scan(tmp_path)
        assert [f["match"] for f in found] == ["1,235"]

    def test_an_uncited_marker_does_not_count(self):
        assert not ced.WAIVER_RE.search("# estate-data-ok:")
