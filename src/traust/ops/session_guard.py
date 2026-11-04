from __future__ import annotations

import json
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path


def decision(
    tool: str, arguments: Mapping[str, object], task: Path, skills: Path, output: Path
) -> bool:
    if tool in {"Read", "Write"}:
        value = arguments.get("file_path")
    elif tool in {"Glob", "Grep"}:
        value = arguments.get("path")
        pattern = arguments.get("pattern", "") if tool == "Glob" else arguments.get("glob", "")
        if (
            not isinstance(pattern, str)
            or Path(pattern).is_absolute()
            or ".." in Path(pattern).parts
        ):
            return False
    elif tool in {"Agent", "Task"}:
        return not arguments.get("isolation")
    else:
        return tool == "Skill"
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        resolved = path.resolve()
        if tool == "Write":
            return resolved == output and not any(p.is_symlink() for p in (path, *path.parents))
        return resolved.is_relative_to(task) or resolved.is_relative_to(skills)
    except (OSError, RuntimeError):
        return False


def main() -> int:
    try:
        task, skills, output = (Path(p).resolve() for p in sys.argv[1:])
        call = json.load(sys.stdin)
        if not isinstance(call, dict) or not isinstance(call.get("tool_input"), dict):
            raise ValueError("invalid hook input")
        allowed = decision(call["tool_name"], call["tool_input"], task, skills, output)
    except (KeyError, TypeError, ValueError, OSError, RuntimeError):
        allowed = False
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow" if allowed else "deny",
                    "permissionDecisionReason": "runner session boundary",
                }
            }
        )
    )
    return 0


def flags(task: Path, skills: Path, output: Path) -> list[str]:
    command = shlex.join(
        [sys.executable, "-m", "traust.ops.session_guard", str(task), str(skills), str(output)]
    )
    settings = {
        "permissions": {"blockReadsOutsideWorkingDirectories": True},
        "hooks": {
            "PreToolUse": [
                {"matcher": ".*", "hooks": [{"type": "command", "command": command, "timeout": 10}]}
            ]
        },
    }
    return [
        "--permission-mode",
        "dontAsk",
        # The user source is the session's own CLAUDE_CONFIG_DIR (a skills-only dir the
        # runner builds): `--restricted` and a blank `--setting-sources` strip Claude's
        # skills entirely, so a session told to run `/dependency-watch` could not resolve
        # it and every artifact-only order died as session-output-invalid. The guard hook
        # stays the single authority on what a call may touch.
        "--setting-sources",
        "user",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--tools",
        "Read,Glob,Grep,Write,Agent,Skill",
        "--disallowedTools",
        "Bash(*traust.cli*)",
        "Bash",
        "Edit",
        "NotebookEdit",
        "WebFetch",
        "WebSearch",
        "mcp__*",
        "--add-dir",
        str(task),
        "--settings",
        json.dumps(settings),
    ]


if __name__ == "__main__":
    raise SystemExit(main())
