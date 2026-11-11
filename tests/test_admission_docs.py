"""The documented finding-admission table matches what traust-core's recording admits.

`docs/cli-reference.md` ("Audit publication versus finding admission") tells every skill which
`reporting record --kind` admits the report's findings. The answer is traust-core's
`REPORTED_FINDINGS` mapping, so the table is checked against it, kind by kind.
"""

from __future__ import annotations

import re
from pathlib import Path

from traust_core.v1.models.assessment import REPORTED_FINDINGS, AssessmentKind

CLI_REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "cli-reference.md"
SECTION = "### Audit publication versus finding admission"
ADMITS = "Core admits the document's findings"


def documented() -> dict[str, bool]:
    text = CLI_REFERENCE.read_text(encoding="utf-8")
    section = text.split(SECTION, 1)[1].split("\n#", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| `")]
    assert rows, f"{CLI_REFERENCE}: no admission table under {SECTION!r}"
    kinds: dict[str, bool] = {}
    for row in rows:
        first, admission = (cell.strip() for cell in row.strip("|").split("|")[:2])
        for kind in re.findall(r"`([a-z_]+)`", first):
            assert kind not in kinds, f"{kind} is listed twice"
            kinds[kind] = admission.startswith(ADMITS)
    return kinds


def test_each_documented_kind_admits_exactly_when_core_admits_it() -> None:
    table = documented()
    assert table, "the admission table names no kind"
    assert {kind: AssessmentKind(kind) in REPORTED_FINDINGS for kind in table} == table
