"""The traust-metrics procedure diffs the scoreboard file its collector step writes."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from traust.paths import skill_dir

SKILL = skill_dir("traust-metrics") / "SKILL.md"


def test_the_report_back_diff_names_the_file_the_collector_writes() -> None:
    text = SKILL.read_text(encoding="utf-8")
    [out] = set(re.findall(r"--out (progress-tracker/\S+)", text))
    written = PurePosixPath(out) / "traust-metrics.md"
    diffs = re.findall(r"git\s+-C\s+progress-tracker\s+diff\s+(\S+?)`", text)
    assert diffs, f"{SKILL}: no `git -C progress-tracker diff` step"
    for path in diffs:
        assert PurePosixPath("progress-tracker") / path == written, path
