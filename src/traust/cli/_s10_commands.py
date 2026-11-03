"""Executable-aware argv checks for the skill-security target-build gate."""

import re
import shlex
from collections.abc import Callable
from pathlib import PurePath

_BUILD_EXECUTABLES = frozenset(
    {"make", "mvn", "gradlew", "gradle", "go", "npm", "cargo", "govulncheck"}
)
_SHELL_EXECUTABLES = frozenset({"sh", "bash", "dash", "ash", "zsh", "ksh"})
_PYTHON_EXECUTABLE_RX = re.compile(r"python(?:\d+(?:\.\d+)*)?(?:\.exe)?\Z")
_ASSIGNMENT_RX = re.compile(r"[A-Za-z_][A-Za-z_0-9]*=")


def unrouted_argv(
    argv: tuple[str | None, ...],
    *,
    build_rx: re.Pattern[str],
    shell_check: Callable[[str], bool],
    python_check: Callable[[str], bool],
) -> bool:
    """Check the program being executed, not build-looking argument data.

    Unknown tokens remain barriers, including in executable and option positions.
    Only a real shell/Python command-string option delegates its payload to a
    language checker; ordinary argv never gains shell syntax by being joined.
    """
    if not argv or argv[0] is None:
        return False
    executable = PurePath(argv[0]).name

    def inspect(command: tuple[str | None, ...]) -> bool:
        return unrouted_argv(
            command, build_rx=build_rx, shell_check=shell_check, python_check=python_check
        )

    def unrouted_wrapper(command: tuple[str | None, ...]) -> bool:
        # A check/lookalike operation is not evidence that its command is routed.
        index = 0
        while index < len(command):
            token = command[index]
            if token is None:
                return False
            if token == "--":
                return inspect(command[index + 1 :])
            if token == "--string":
                return (
                    index + 1 < len(command)
                    and command[index + 1] is not None
                    and shell_check(command[index + 1])
                )
            if token == "--profile":
                index += 2
            elif token.startswith("-"):
                index += 1
            else:
                return inspect(command[index:])
        return False

    if executable == "traust":
        if argv[1:4] == ("util", "safe-exec", "run"):
            return False
        if len(argv) > 2 and argv[1] == "util" and argv[2] is not None:
            if argv[2] == "safe-exec":
                return unrouted_wrapper(argv[4:])
            if argv[2].startswith("safe-exec"):
                return unrouted_wrapper(argv[3:])
        return False

    if executable == "safe_exec.py":
        return False if argv[1:2] == ("run",) else unrouted_wrapper(argv[2:])

    if executable == "env":
        index = 1
        while index < len(argv):
            option = argv[index]
            if option is None:
                return False
            if option == "--":
                return inspect(argv[index + 1 :])
            if _ASSIGNMENT_RX.match(option):
                index += 1
            elif option in {"-u", "--unset", "-C", "--chdir"}:
                index += 2
            elif option in {"-", "-i", "--ignore-environment"} or option.startswith(
                ("--unset=", "--chdir=")
            ):
                index += 1
            elif option.startswith("-"):
                return False
            else:
                return inspect(argv[index:])
        return False

    if executable in _SHELL_EXECUTABLES:
        index = 1
        while index < len(argv):
            option = argv[index]
            if option is None or option in {"-", "--"} or not option.startswith(("-", "+")):
                return False
            if option.startswith("-") and not option.startswith("--") and "c" in option[1:]:
                return (
                    index + 1 < len(argv)
                    and argv[index + 1] is not None
                    and shell_check(argv[index + 1])
                )
            index += 2 if option in {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"} else 1
        return False

    if _PYTHON_EXECUTABLE_RX.fullmatch(executable):
        index = 1
        while index < len(argv):
            option = argv[index]
            if option is None:
                return False
            if option == "--":
                script = argv[index + 1 :]
                return bool(
                    script
                    and script[0] is not None
                    and PurePath(script[0]).name == "safe_exec.py"
                    and inspect(script)
                )
            if option.startswith("-") and not option.startswith("--"):
                flags = option[1:]
                offset = 0
                while offset < len(flags):
                    flag = flags[offset]
                    if flag in {"c", "m"}:
                        inline = flags[offset + 1 :]
                        payload = inline or (argv[index + 1] if index + 1 < len(argv) else None)
                        if payload is None:
                            return False
                        if flag == "c":
                            return python_check(payload)
                        if payload == "traust.cli":
                            rest = index + 1 if inline else index + 2
                            return inspect(("traust", *argv[rest:]))
                        return False
                    if flag in {"W", "X"}:
                        if offset + 1 == len(flags):
                            index += 1
                        break
                    offset += 1
            if not option.startswith("-") or option == "-":
                if PurePath(option).name == "safe_exec.py":
                    return inspect(argv[index:])
                return False
            index += 2 if option == "--check-hash-based-pycs" else 1
        return False

    if executable not in _BUILD_EXECUTABLES:
        return False
    # Quoting keeps a token containing spaces/metacharacters from masquerading
    # as several argv entries. The sentinel is deliberately not an empty token.
    head = "./gradlew" if executable == "gradlew" else executable
    arguments = (shlex.quote(token) if token is not None else "\x00" for token in argv[1:])
    command = " ".join((head, *arguments))
    return build_rx.match(command) is not None


def _shell_end(text: str, start: int, closing: str) -> int:
    """Find a shell quote/substitution end without flattening nested syntax."""
    if closing == "'":
        end = text.find("'", start)
        if end < 0:
            raise ValueError("Unclosed shell quote")
        return end
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == closing:
            return index
        if text.startswith("$(", index):
            index = _shell_end(text, index + 2, ")") + 1
        elif char == "`" and closing != "`":
            index = _shell_end(text, index + 1, "`") + 1
        elif closing == ")" and char in "'\"(":
            index = _shell_end(text, index + 1, ")" if char == "(" else char) + 1
        else:
            index += 1
    raise ValueError("Unclosed shell quote or substitution")


def _shell_tokens(text: str) -> list[tuple[str, str]]:
    """Keep word spelling separate from unquoted shell control operators."""
    tokens: list[tuple[str, str]] = []
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in "'\"`":
            index = _shell_end(text, index + 1, char) + 1
            continue
        if text.startswith("$(", index):
            index = _shell_end(text, index + 2, ")") + 1
            continue
        if char == "#" and start == index:
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            start = index
            continue
        if char.isspace() or char in ";&|()<>":
            word = text[start:index]
            if word and not (char in "<>" and word.isdigit()):
                tokens.append(("word", word))
            if char in "<>":
                end = index + 1
                while end < len(text) and text[end] in "<>&|":
                    end += 1
                tokens.append(("redirect", text[index:end]))
                index = end
            else:
                if char == "\n" or char in ";&|()":
                    tokens.append(("control", char))
                index += 1
            start = index
            continue
        index += 1
    if start < len(text):
        tokens.append(("word", text[start:]))
    return tokens


def _shell_word(
    raw: str,
    variables: dict[str, str | None],
    shell_check: Callable[[str], bool],
    *,
    split: bool = True,
) -> tuple[tuple[str | None, ...], bool]:
    """Remove quotes while inspecting only substitutions the shell evaluates."""
    result: list[str] = []
    quote = ""
    unknown = False
    blocked = False
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "'" and not quote:
            end = _shell_end(raw, index + 1, "'")
            result.append(raw[index + 1 : end])
            index = end + 1
            continue
        if char == '"':
            quote = "" if quote else '"'
            index += 1
            continue
        if char == "\\" and index + 1 < len(raw):
            following = raw[index + 1]
            if not quote or following in '$`"\\\n':
                if following != "\n":
                    result.append(following)
                index += 2
                continue
        if raw.startswith("$(", index) or char == "`":
            offset = 2 if char == "$" else 1
            end = _shell_end(raw, index + offset, ")" if char == "$" else "`")
            payload = raw[index + offset : end]
            if char == "$" and payload.startswith("("):
                # Arithmetic is not a command string, but nested command
                # substitutions in its expression still execute.
                _, nested = _shell_word(payload, variables, shell_check)
                blocked |= nested
            else:
                blocked |= shell_check(payload)
            unknown = True
            index = end + 1
            continue
        if char == "$":
            match = re.match(
                r"\$(?:([A-Za-z_][A-Za-z_0-9]*)|\{([A-Za-z_][A-Za-z_0-9]*)\})", raw[index:]
            )
            if match:
                value = variables.get(match[1] or match[2])
                if value is None:
                    unknown = True
                elif split and not quote:
                    result.append(re.sub(r"[ \t\n]+", "\x00", value))
                else:
                    result.append(value)
                index += match.end()
                continue
            if index + 1 < len(raw) and raw[index + 1] in "{0123456789@*#?$!-":
                unknown = True
        result.append(char)
        index += 1
    if unknown:
        return (None,), blocked
    value = "".join(result)
    fields = tuple(field for field in value.split("\x00") if field)
    return (fields if "\x00" in value else (value,)), blocked


def unrouted_shell(
    text: str,
    *,
    build_rx: re.Pattern[str],
    python_check: Callable[[str], bool],
) -> bool:
    """Inspect executable shell words, keeping quoted argument data inert.

    Literal variable bindings are tracked; unsupported/dynamic expansions remain
    unknown argv barriers rather than being evaluated as shell source. Command
    substitutions are checked before routing, because the calling shell executes
    them even when the resulting argv belongs to an exact safe-exec route.
    """

    def shell_check(payload: str) -> bool:
        return unrouted_shell(payload, build_rx=build_rx, python_check=python_check)

    variables: dict[str, str | None] = {}

    def inspect(tokens: list[tuple[str, str]]) -> bool:
        argv: list[str | None] = []
        assignments: dict[str, str | None] = {}
        redirect = False
        for kind, raw in tokens:
            if kind == "redirect":
                redirect = True
                continue
            assignment = _ASSIGNMENT_RX.match(raw) if not argv and not redirect else None
            value, blocked = _shell_word(
                raw[assignment.end() :] if assignment else raw,
                variables,
                shell_check,
                split=assignment is None,
            )
            if blocked:
                return True
            if redirect:
                redirect = False
            elif assignment:
                assignments[raw[: assignment.end() - 1]] = value[0]
            else:
                argv.extend(value)
        if not argv:
            variables.update(assignments)
            return False
        while argv and argv[0] in {"if", "then", "elif", "else", "while", "until", "do", "!"}:
            argv.pop(0)
        return unrouted_argv(
            tuple(argv), build_rx=build_rx, shell_check=shell_check, python_check=python_check
        )

    try:
        tokens = _shell_tokens(re.sub(r"\\\r?\n", "", text))
    except ValueError:
        # A malformed payload cannot establish a safe route.
        return build_rx.search(text) is not None
    command: list[tuple[str, str]] = []
    for kind, raw in [*tokens, ("control", ";")]:
        if kind == "control":
            if inspect(command):
                return True
            command = []
        else:
            command.append((kind, raw))
    return False
