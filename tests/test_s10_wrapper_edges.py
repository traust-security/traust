"""Paired execution/data regressions for all ten S10 command review findings."""

import pytest

from tests.test_check_skill_security import CLEAN_SKILL, _mk_repo
from traust.cli import check_skill_security as css
from traust.cli._s10_commands import unrouted_shell


def _s10_failures(tmp_path, script):
    repo = _mk_repo(tmp_path, skill_md=CLEAN_SKILL, script=script, script_name="run.py")
    failures, _ = css.security_failures(repo)
    return [failure for failure in failures if failure.startswith("S10")]


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("argv", "blocked"),
    [
        pytest.param(["go build ./..."], True, id="shell-list-first-payload"),
        pytest.param(["echo ok; go build"], True, id="shell-list-sequence"),
        pytest.param(["echo ok", "go build"], False, id="shell-list-rest-is-not-source"),
        pytest.param(["echo", "go build"], False, id="shell-list-positional-data"),
        pytest.param(["echo '$(go build)'"], False, id="shell-list-quoted-data"),
        pytest.param(["traust util safe-exec run -- go build"], False, id="shell-list-routed"),
    ],
)
def test_shell_true_sequence_uses_only_first_shell_payload(tmp_path, argv, blocked):
    script = f"import subprocess\nsubprocess.run({argv!r}, shell=True)\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize(
    "operation",
    [
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
    ],
)
@pytest.mark.parametrize("blocked", [True, False], ids=["go-path-echo-argv0", "echo-path-go-argv0"])
def test_os_execution_path_overrides_argv_zero(tmp_path, operation, blocked):
    path = "/usr/bin/go" if blocked else "/bin/echo"
    argv0 = "echo" if blocked else "go"
    family = operation.removeprefix("spawn").removeprefix("exec")
    command = repr([argv0, "build"]) if family.startswith("v") else f"{argv0!r}, 'build'"
    mode = "os.P_WAIT, " if operation.startswith("spawn") else ""
    environment = ", {}" if operation.endswith("e") else ""
    script = f"import os\nos.{operation}({mode}{path!r}, {command}{environment})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.parametrize(
    ("command", "blocked"),
    [
        pytest.param("echo ';' go build", False, id="quoted-semicolon-data"),
        pytest.param("echo ; go build", True, id="real-semicolon"),
        pytest.param("echo '$(go build)'", False, id="single-quoted-substitution-data"),
        pytest.param('echo "$(go build)"', True, id="double-quoted-substitution"),
        pytest.param("echo $(go build)", True, id="unquoted-substitution"),
        pytest.param("echo '`go build`'", False, id="single-quoted-backtick-data"),
        pytest.param('echo "`go build`"', True, id="double-quoted-backticks"),
        pytest.param("echo `go build`", True, id="unquoted-backticks"),
        pytest.param("echo $(echo 'go build')", False, id="substitution-echo-data"),
        pytest.param(
            "traust util safe-exec run -- echo ';' go build",
            False,
            id="routed-quoted-semicolon-data",
        ),
        pytest.param(
            "traust util safe-exec run -- echo '$(go build)'",
            False,
            id="routed-single-quoted-substitution-data",
        ),
        pytest.param(
            'traust util safe-exec run -- echo "$(go build)"',
            True,
            id="substitution-executes-before-route",
        ),
        pytest.param(
            "traust util safe-exec run -- echo `go build`",
            True,
            id="backticks-execute-before-route",
        ),
        pytest.param(
            "python3 safe_exec.py run -- echo '$(go build)'",
            False,
            id="script-route-single-quoted-data",
        ),
        pytest.param(
            'python3 safe_exec.py run -- echo "$(go build)"',
            True,
            id="substitution-executes-before-script-route",
        ),
        pytest.param("$COMMAND build", False, id="unknown-command-is-not-an-invented-head"),
        pytest.param('echo "$COMMAND" go build', False, id="unknown-echo-data"),
    ],
)
def test_shell_quote_provenance_distinguishes_execution_and_data(command, blocked):
    assert (
        unrouted_shell(command, build_rx=css.S10_BUILD_RX, python_check=css._s10_unrouted_build)
        is blocked
    )


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("command", "blocked"),
    [
        ("echo ';' go build", False),
        ("echo ; go build", True),
        ("echo '$(go build)'", False),
        ('echo "$(go build)"', True),
        ("traust util safe-exec run -- echo '$(go build)'", False),
        ('traust util safe-exec run -- echo "$(go build)"', True),
    ],
)
def test_python_shell_payload_uses_quote_preserving_classifier(tmp_path, command, blocked):
    script = f"import os\nos.system({command!r})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("unknown", "known", "blocked"),
    [
        ("go build", "echo ok", True),
        ("go build", "traust util safe-exec run -- go build", True),
        ("echo go build", "echo ok", False),
        ("traust util safe-exec run -- go build", "echo ok", False),
    ],
)
def test_known_alternative_does_not_hide_unknown_command_candidate(
    tmp_path, unknown, known, blocked
):
    script = (
        "import os\n"
        "def identity(command):\n    return command\n"
        f"CMD = identity({unknown!r}) if flag else {known!r}\n"
        "os.system(CMD)\n"
    )
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize("argv", [["echo", "go build"], ["printf", "%s", "cargo build"]])
@pytest.mark.parametrize(
    "execute", [False, True], ids=["proven-data-only", "separate-real-command"]
)
def test_dynamic_fallback_does_not_promote_proven_argv_data(tmp_path, argv, execute):
    script = (
        "import subprocess\n"
        "def compute_command():\n    return ['echo', 'ok']\n"
        "def identity(command):\n    return command\n"
        f"subprocess.run({argv!r})\n"
        "subprocess.run(compute_command())\n"
    )
    if execute:
        script += "subprocess.run(identity('go build'))\n"
    assert bool(_s10_failures(tmp_path, script)) is execute


@pytest.mark.requires_git
@pytest.mark.parametrize("outer", ["safe_exec.run", "print"])
@pytest.mark.parametrize(
    ("command", "blocked"),
    [
        ("go build", True),
        ("echo go build", False),
        ("traust util safe-exec run -- go build", False),
    ],
)
def test_inert_outer_call_does_not_hide_nested_dynamic_execution(tmp_path, outer, command, blocked):
    script = (
        "import os\n"
        "from traust_engine._util import safe_exec\n"
        "def identity(command):\n    return command\n"
        f"{outer}(os.system(identity({command!r})))\n"
    )
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("expression", "blocked"),
    [
        pytest.param("'echo ok; go build'", True, id="sequenced-candidate"),
        pytest.param("'go ' + 'build'", True, id="composed-candidate"),
        pytest.param("'echo ok; ' + 'go build'", True, id="composed-sequence"),
        pytest.param("'echo go build'", False, id="echo-candidate-data"),
        pytest.param("\"echo 'go build; cargo build'\"", False, id="quoted-sequence-data"),
        pytest.param("'echo ' + 'go build'", False, id="composed-echo-data"),
        pytest.param(
            "'traust util safe-exec run -- ' + 'go build'",
            False,
            id="composed-routed-candidate",
        ),
    ],
)
def test_dynamic_fallback_inspects_whole_constructed_shell_candidates(
    tmp_path, expression, blocked
):
    script = (
        "import os\n"
        "def identity(command):\n    return command\n"
        f"os.system(identity({expression}))\n"
    )
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("command", "blocked"),
    [
        ("env go build", True),
        ("env TARGET=checkout go build", True),
        ("env -u TARGET go build", True),
        ("env -- go build", True),
        ("TARGET=checkout go build", True),
        ("FIRST=one SECOND=two go build", True),
        ("COMMAND=go; $COMMAND build", True),
        ("COMMAND='go build'; $COMMAND", True),
        ("env echo go build", False),
        ("TARGET=checkout echo go build", False),
        ("TARGET='go build'", False),
        ("echo TARGET=checkout go build", False),
        ("'TARGET=checkout' go build", False),
        ("COMMAND='go build'; echo $COMMAND", False),
        ("COMMAND='echo go build'; $COMMAND", False),
        ("TARGET=checkout traust util safe-exec run -- go build", False),
    ],
)
def test_shell_assignment_and_env_prefixes_reach_actual_executable(tmp_path, command, blocked):
    script = f"import os\nos.system({command!r})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("argv", "blocked"),
    [
        (["env", "go", "build"], True),
        (["env", "TARGET=checkout", "go", "build"], True),
        (["env", "echo", "go", "build"], False),
        (["env", "traust", "util", "safe-exec", "run", "--", "go", "build"], False),
        (["bash", "-O", "extglob", "-c", "go build"], True),
        (["bash", "-O", "extglob", "-c", "echo go build"], False),
        (["bash", "-O", "extglob", "script.sh", "-c", "go build"], False),
        (["bash", "-O", "extglob", "-c", "traust util safe-exec run -- go build"], False),
        (["python3", "-Ic", "import os; os.system('go build')"], True),
        (["python3", "-uc", "import os; os.system('go build')"], True),
        (["python3", "-Icimport os; os.system('go build')"], True),
        (["python3", "-Ic", "print('go build')"], False),
        (["python3", "-uc", "print('go build')"], False),
        (["python3", "-W", "ignore", "-Ic", "import os; os.system('go build')"], True),
        (["python3", "-Wignore", "-Ic", "print('go build')"], False),
        (["python3", "-I", "script.py", "-uc", "go build"], False),
        (["python3", "-Im", "traust.cli", "util", "safe-exec", "run", "--", "go", "build"], False),
    ],
)
def test_wrapper_options_do_not_conceal_payload_or_reclassify_script_data(tmp_path, argv, blocked):
    script = f"import subprocess\nsubprocess.run({argv!r})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("expression", "blocked"),
    [
        pytest.param(
            "shlex.split(\"go 'build'\", posix=False)", False, id="non-posix-quotes-retained"
        ),
        pytest.param("shlex.split(\"go 'build'\", posix=True)", True, id="posix-quotes-removed"),
        pytest.param("shlex.split(\"go 'build'\", False, False)", False, id="positional-non-posix"),
        pytest.param('shlex.split("go build", posix=False)', True, id="non-posix-real-build"),
        pytest.param(
            "shlex.split(\"echo 'go build'\", posix=False)", False, id="non-posix-echo-data"
        ),
        pytest.param(
            'shlex.split("go # comment\\nbuild", comments=True)', True, id="comments-enabled"
        ),
        pytest.param(
            'shlex.split("go # comment\\nbuild", comments=False)', False, id="comment-token-barrier"
        ),
    ],
)
def test_shlex_split_options_determine_actual_argv(tmp_path, expression, blocked):
    script = f"import shlex\nimport subprocess\nsubprocess.run({expression})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked
