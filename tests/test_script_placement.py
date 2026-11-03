from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest
from traust_core.v1.errors import ValidationError

from traust.cli.__main__ import main
from traust.cli.classify_script_placement import classify


@pytest.fixture
def harness(tmp_path: Path) -> Path:
    tmp_path = tmp_path / "harness, with spaces"
    cli = tmp_path / "src" / "traust" / "cli"
    cli.mkdir(parents=True)
    for name in ("shared", "multi", "single", "orphan", "other"):
        (cli / f"{name}.py").write_text("VALUE = 1\n", encoding="utf-8")
    readers = tmp_path / "src" / "traust" / "lib"
    readers.mkdir()
    for index, statement in enumerate(
        ("from traust.cli import shared", "import traust.cli.shared", "from shared import VALUE")
    ):
        (readers / f"reader{index}.py").write_text(statement + "\n", encoding="utf-8")
    (readers / "other.py").write_text("from traust.cli.other import VALUE\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_uses.py").write_text(
        "from traust.cli import shared, single, orphan\n", encoding="utf-8"
    )
    first = tmp_path / "harnessing" / "3-audit" / "first"
    first.mkdir(parents=True)
    (first / "SKILL.md").write_text("Run multi.py and single.py.\n", encoding="utf-8")
    second = tmp_path / "harnessing" / "second"
    second.mkdir()
    (second / "SKILL.md").write_text("Run python -m traust.cli.multi.\n", encoding="utf-8")
    return tmp_path


def test_import_and_skill_thresholds_do_not_count_tests_as_production_callers(
    harness: Path,
) -> None:
    rows, counts = classify(harness)
    by_name = {row.module: row for row in rows}
    assert {name: row.classification for name, row in by_name.items()} == {
        "shared": "shared-library",
        "multi": "multi-skill-cli",
        "single": "single-skill-cli",
        "orphan": "orphan",
        "other": "other",
    }
    assert by_name["shared"].non_test_importers == 3
    assert by_name["shared"].total_importers == 4
    assert by_name["single"].non_test_importers == 0
    assert counts == {
        name: 1
        for name in ("shared-library", "multi-skill-cli", "single-skill-cli", "orphan", "other")
    }


def test_grouped_cli_filters_rows_without_narrowing_summary(harness: Path, capsys) -> None:
    assert main(["check", "script-placement", "--root", str(harness), "--only", "orphan"]) == 0
    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    boundary = rows.index([])
    assert dict(rows[1:boundary])["shared-library"] == "1"
    header, values = rows[boundary + 1 :]
    row = dict(zip(header, values, strict=True))
    assert row["module"] == "orphan"
    assert row["non_test_importers"] == "0"
    assert Path(row["path"]) == harness / "src" / "traust" / "cli" / "orphan.py"


def test_unreadable_python_is_not_reported_as_an_unused_module(harness: Path) -> None:
    (harness / "src" / "traust" / "lib" / "broken.py").write_text("def broken(\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        classify(harness)
