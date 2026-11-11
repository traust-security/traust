from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from traust.ops.session_guard import decision


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    task, skills = tmp_path / "task", tmp_path / "skills"
    (task / "output").mkdir(parents=True)
    (task / "input").mkdir()
    skills.mkdir()
    return task.resolve(), skills.resolve(), (task / "output/verdicts.json").resolve()


@pytest.mark.parametrize("tool", ["Read", "Glob", "Grep"])
def test_reads_are_limited_to_task_and_skills(roots: tuple[Path, Path, Path], tool: str) -> None:
    task, skills, _output = roots
    field = "file_path" if tool == "Read" else "path"
    for permitted in (task / "input", skills):
        assert decision(tool, {field: str(permitted)}, *roots)
    assert not decision(tool, {field: str(task.parent)}, *roots)
    assert not decision(tool, {}, *roots)
    (task / "input/escape").symlink_to(task.parent)
    assert not decision(tool, {field: str(task / "input/escape")}, *roots)


@pytest.mark.parametrize("pattern", ["../*", "/etc/*", "input/../../*"])
def test_search_patterns_cannot_escape_the_checked_root(
    roots: tuple[Path, Path, Path], pattern: str
) -> None:
    assert not decision("Glob", {"path": str(roots[0]), "pattern": pattern}, *roots)


def test_only_the_declared_output_is_writable(roots: tuple[Path, Path, Path]) -> None:
    task, skills, output = roots
    assert decision("Write", {"file_path": str(output)}, *roots)
    for other in (
        task / "task.json",
        task / "input/data",
        skills / "SKILL.md",
        task / "output/extra.json",
    ):
        assert not decision("Write", {"file_path": str(other)}, *roots)
    output.symlink_to(task.parent / "outside")
    assert not decision("Write", {"file_path": str(output)}, *roots)


@pytest.mark.parametrize(
    "tool", ["Bash", "PowerShell", "Edit", "NotebookEdit", "WebFetch", "mcp__db__write"]
)
def test_indirect_io_tools_are_denied(roots: tuple[Path, Path, Path], tool: str) -> None:
    assert not decision(
        tool, {"command": "python3 -m traust.cli impact below-range-record x"}, *roots
    )


def test_subagents_keep_the_same_workspace(roots: tuple[Path, Path, Path]) -> None:
    assert decision("Agent", {"prompt": "review staged inputs"}, *roots)
    assert not decision("Agent", {"isolation": "worktree"}, *roots)


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[]",
        '{"tool_name":"Read","tool_input":[]}',
        '{"tool_name":"Glob","tool_input":{"path":"/","pattern":3}}',
    ],
)
def test_malformed_hook_input_fails_closed(roots: tuple[Path, Path, Path], payload: str) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "traust.ops.session_guard", *map(str, roots)],
        input=payload,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
