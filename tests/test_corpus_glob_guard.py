#!/usr/bin/env python3
"""Guard: committed tooling must not enumerate the corpus with a raw glob.

`analysis-results/findings/_orgs/` is an index of SYMLINKS into the canonical
report paths. A recursive glob follows them, so the same physical file is
counted many times — measured 2026-08-13, a recursive glob returned about
2.6x the distinct report count, an inflation that produced wrong figures in
three shipped changelog entries. Git also refuses to traverse those paths
(`git ls-files --error-unmatch` and `git show HEAD:<path>` fail with "beyond a
symbolic link"), so a symlinked report reads as untracked or brand-new — which
twice made a migration's "is this file's only change mine?" check declare 100
clean files entangled with other people's work.

`traust_engine.corpus.resolver` gets this right (`os.walk(followlinks=False)`, symlinked
dirs dropped and recorded as aliases). Use `walk_reports()` or
`iter_report_paths()` / `resolve()`; resolve through `canonical()` before any git call.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[1]
SEARCH_DIRS = ("src/traust", "harnessing")

#: The shape that actually breaks: glob.glob/iglob with recursive=True.
#
# Measured 2026-08-13 on Python 3.14 against the real corpus:
#   glob.glob("findings/**/*-security-audit.json", recursive=True)
#       -> 2.65x inflation over distinct reports  (FOLLOWS dir symlinks)
#   Path("findings").rglob("*-security-audit.json")
#       -> 1.01x                                   (does NOT, 3.13+)
#
# So pathlib's rglob is nearly safe — it still lists ~100 FILE symlinks sitting
# in real directories, a 1.2% overcount worth fixing in anything that publishes
# a number, but not the 2.6x catastrophe. An earlier version of this guard
# flagged every glob of a report artefact and produced 22 "offenders", 21 of
# which were pathlib or directory-scoped and materially fine. Flagging the wrong
# shape is worse than not flagging: it buries the one real defect in noise.
_RECURSIVE_GLOB_RX = re.compile(
    r"""glob\.i?glob\s*\((?:[^()]|\([^()]*\))*?"""
    r"""-(?:security-audit|findings-layer|findings-current|triage|threat-model)"""
    r"""(?:[^()]|\([^()]*\))*?recursive\s*=\s*True""",
    re.S,
)

#: correct by design — walking aliases is harmless or intended here
EXEMPT: dict[str, str] = {}


class TestNoRawCorpusGlob(unittest.TestCase):
    def test_no_raw_glob_of_corpus_reports(self):
        offenders = []
        for d in SEARCH_DIRS:
            for py in sorted((HARNESS_ROOT / d).rglob("*.py")):
                rel = py.relative_to(HARNESS_ROOT).as_posix()
                if rel in EXEMPT:
                    continue
                try:
                    src = py.read_text(encoding="utf-8")
                except OSError:
                    continue
                if _RECURSIVE_GLOB_RX.search(src):
                    offenders.append(rel)
        self.assertEqual(
            offenders,
            [],
            "these enumerate corpus reports with a raw glob, which follows the "
            "findings/_orgs symlink index and double-counts 2.65x:\n  "
            + "\n  ".join(offenders)
            + "\nUse corpus.iter_report_paths() / corpus.resolve(), or add a "
            "cited exemption to EXEMPT in this test explaining why aliases "
            "are harmless there.",
        )

    def test_exemptions_are_cited(self):
        for path, reason in EXEMPT.items():
            self.assertTrue((HARNESS_ROOT / path).exists(), f"stale exemption: {path}")
            self.assertGreater(len(reason), 25, f"exemption for {path} needs a real reason")


if __name__ == "__main__":
    unittest.main()
