"""Consumer-visible regressions for executable-aware S10 command values."""

import pytest

from tests.test_check_skill_security import CLEAN_SKILL, _mk_repo
from traust.cli import check_skill_security as css


def _s10_failures(tmp_path, script, *, skill=CLEAN_SKILL):
    repo = _mk_repo(tmp_path, skill_md=skill, script=script, script_name="run.py")
    failures, _ = css.security_failures(repo)
    return [failure for failure in failures if failure.startswith("S10")]


def _argv_expression(argv):
    # Unresolved names represent unknown tokens, not empty strings to join away.
    return "[" + ", ".join(repr(token) if token is not None else "dynamic" for token in argv) + "]"


@pytest.mark.requires_git
@pytest.mark.parametrize("variable", [False, True], ids=["literal-argv", "variable-argv"])
@pytest.mark.parametrize(
    ("argv", "blocked"),
    [
        pytest.param(("go", "build", "./..."), True, id="go-build"),
        pytest.param(("/usr/local/bin/go", "test", "./..."), True, id="path-go-test"),
        pytest.param(("cargo", "build"), True, id="cargo-build"),
        pytest.param(("/opt/bin/cargo", "test"), True, id="path-cargo-test"),
        pytest.param(("cargo", "fuzz", "run", "target"), True, id="cargo-fuzz"),
        pytest.param(("npm", "ci"), True, id="npm-ci"),
        pytest.param(("/usr/bin/npm", "run", "build"), True, id="path-npm-build"),
        pytest.param(("make", "build"), True, id="make-build"),
        pytest.param(("/usr/bin/make", "install"), True, id="path-make-install"),
        pytest.param(("mvn", "-B", "-DskipTests", "package"), True, id="maven-package"),
        pytest.param(("/opt/bin/gradle", "test"), True, id="path-gradle-test"),
        pytest.param(("./gradlew", "assemble"), True, id="gradle-wrapper"),
        pytest.param(("/checkout/gradlew", "build"), True, id="path-gradle-wrapper"),
        pytest.param(("govulncheck", "./..."), True, id="govulncheck-target"),
        pytest.param(
            ("/opt/bin/govulncheck", "-mode", "source", "./..."), True, id="path-govulncheck"
        ),
        pytest.param(("go", "version"), False, id="go-version"),
        pytest.param(("cargo", "--version"), False, id="cargo-version"),
        pytest.param(("npm", "--version"), False, id="npm-version"),
        pytest.param(("govulncheck", "-version"), False, id="govulncheck-version"),
        pytest.param(("echo", "go", "build"), False, id="echo-token-data"),
        pytest.param(("/bin/echo", "go build ./..."), False, id="path-echo-string-data"),
        pytest.param(("printf", "go build"), False, id="printf-build-data"),
        pytest.param(("printf", "%s\\n", "cargo build"), False, id="printf-cargo-data"),
        pytest.param(("echo", "ok; go build ./..."), False, id="literal-semicolon"),
        pytest.param(("echo", "$(go build ./...)"), False, id="literal-substitution"),
        pytest.param(("echo", "`cargo build`"), False, id="literal-backticks"),
        pytest.param(("go", "version", ";", "cargo", "build"), False, id="argv-not-shell"),
        pytest.param(("go", "build ./..."), False, id="one-token-is-not-two"),
        pytest.param(("go", "build; echo"), False, id="subcommand-not-shell-syntax"),
        pytest.param(("go", None, "build"), False, id="unknown-between-tool-and-operation"),
        pytest.param(("go", "build", None), True, id="unknown-target-keeps-known-build"),
        pytest.param(("npm", "run", None, "build"), False, id="unknown-between-npm-operation"),
        pytest.param((None, "go", "build"), False, id="unknown-executable"),
        pytest.param(("echo", None, "go", "build"), False, id="unknown-echo-argument"),
    ],
)
def test_s10_argv_checks_executable_not_argument_data(tmp_path, argv, blocked, variable):
    expression = _argv_expression(argv)
    binding = f"COMMAND = {expression}\n" if variable else ""
    argument = "COMMAND" if variable else expression
    script = (
        "import subprocess\n"
        "from traust_engine._util import safe_exec\n"
        f"{binding}subprocess.run({argument})\n"
    )
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize("variable", [False, True], ids=["literal-argv", "variable-argv"])
@pytest.mark.parametrize(
    ("argv", "blocked"),
    [
        pytest.param(
            ("traust", "util", "safe-exec", "run", "--", "go", "build"), False, id="grouped-run"
        ),
        pytest.param(
            (
                "/venv/bin/traust",
                "util",
                "safe-exec",
                "run",
                "--profile",
                None,
                "--",
                "cargo",
                "build",
            ),
            False,
            id="path-grouped-run",
        ),
        pytest.param(
            ("python3", "-m", "traust.cli", "util", "safe-exec", "run", "--", "go", "build"),
            False,
            id="module-run",
        ),
        pytest.param(
            (
                "/venv/bin/python3",
                "-I",
                "-m",
                "traust.cli",
                "util",
                "safe-exec",
                "run",
                "--",
                "cargo",
                "build",
            ),
            False,
            id="path-module-run",
        ),
        pytest.param(
            ("python3", "safe_exec.py", "run", "--", "go", "build"), False, id="script-run"
        ),
        pytest.param(
            ("/venv/bin/python3.11", "/harness/safe_exec.py", "run", "--", "cargo", "build"),
            False,
            id="path-script-run",
        ),
        pytest.param(
            ("traust", "util", "safe-exec", "check", "--", "go", "build"),
            True,
            id="grouped-check-not-run",
        ),
        pytest.param(
            ("python3", "-m", "traust.cli", "util", "safe-exec", "check", "--", "cargo", "build"),
            True,
            id="module-check-not-run",
        ),
        pytest.param(
            ("python3", "safe_exec.py", "check", "--", "go", "build"),
            True,
            id="script-check-not-run",
        ),
        pytest.param(
            ("traust", "util", "safe-exec-not-wrapper", "go", "build"),
            True,
            id="lookalike-operation",
        ),
        pytest.param(
            ("traust", "util", "safe-exec", "runner", "--", "cargo", "build"),
            True,
            id="lookalike-run",
        ),
        pytest.param(
            ("traust", "util", "safe-exec", "run", "--", "echo", "$(go build)"),
            False,
            id="routed-argv-not-shell",
        ),
        pytest.param(
            ("traust", "util", "safe-exec", "check", "--", "echo", "go", "build"),
            False,
            id="check-of-inert-data",
        ),
    ],
)
def test_s10_only_exact_safe_exec_run_argv_routes(tmp_path, argv, blocked, variable):
    expression = _argv_expression(argv)
    binding = f"COMMAND = {expression}\n" if variable else ""
    argument = "COMMAND" if variable else expression
    script = f"import subprocess\n{binding}subprocess.run({argument})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize("variable", [False, True], ids=["literal-argv", "variable-argv"])
@pytest.mark.parametrize(
    ("argv", "blocked"),
    [
        pytest.param(("bash", "-c", "go build ./..."), True, id="shell-command"),
        pytest.param(("/bin/bash", "-lc", "cargo build"), True, id="shell-login-command"),
        pytest.param(("sh", "-c", "printf '%s\\n' 'go build'"), False, id="shell-printf-data"),
        pytest.param(("bash", "-lc", "echo 'cargo build'"), False, id="shell-echo-data"),
        pytest.param(
            ("bash", "-c", "traust util safe-exec run -- go build ./..."),
            False,
            id="shell-routed-command",
        ),
        pytest.param(
            ("bash", "-c", "traust util safe-exec run -- go test; go build"),
            True,
            id="shell-raw-after-route",
        ),
        pytest.param(("bash", "script.sh", "-c", "go build"), False, id="shell-script-arguments"),
        pytest.param(("bash", "-c", None, "go", "build"), False, id="unknown-shell-payload"),
        pytest.param(
            ("python3", "-c", "import subprocess; subprocess.run(['go', 'build', './...'])"),
            True,
            id="python-command",
        ),
        pytest.param(
            ("/venv/bin/python3.11", "-I", "-c", "import os; os.system('cargo build')"),
            True,
            id="path-python-command",
        ),
        pytest.param(("python3", "-c", "print('go build ./...')"), False, id="python-print-data"),
        pytest.param(
            (
                "python3",
                "-c",
                "from traust_engine._util import safe_exec; safe_exec.run(['cargo', 'build'])",
            ),
            False,
            id="python-routed-command",
        ),
        pytest.param(("python3", "-c", None, "go", "build"), False, id="unknown-python-payload"),
        pytest.param(
            ("python3", "script.py", "-c", "go build"), False, id="python-script-arguments"
        ),
        pytest.param(("python3", "--", "go", "build"), False, id="python-script-not-executable"),
    ],
)
def test_s10_actual_shell_and_python_wrappers_inspect_only_payload(
    tmp_path, argv, blocked, variable
):
    expression = _argv_expression(argv)
    binding = f"COMMAND = {expression}\n" if variable else ""
    argument = "COMMAND" if variable else expression
    script = f"import subprocess\n{binding}subprocess.run({argument})\n"
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize("expression", ["CMD", "CMD.split()", "shlex.split(CMD)"])
@pytest.mark.parametrize(
    ("command", "blocked"),
    [
        pytest.param("go build ./...", True, id="go-build"),
        pytest.param("cargo build", True, id="cargo-build"),
        pytest.param("traust util safe-exec run -- go build ./...", False, id="grouped-run"),
        pytest.param(
            "python3 -m traust.cli util safe-exec run -- cargo build", False, id="module-run"
        ),
        pytest.param("python3 safe_exec.py run -- cargo build", False, id="script-run"),
        pytest.param("traust util safe-exec check -- go build ./...", True, id="check-not-run"),
        pytest.param("echo go build", False, id="echo-data"),
        pytest.param("printf 'cargo build'", False, id="printf-data"),
    ],
)
def test_s10_literal_command_variables_and_split_values(tmp_path, expression, command, blocked):
    script = (
        "import shlex\n"
        "import subprocess\n"
        "from traust_engine._util import safe_exec\n"
        f"CMD = {command!r}\n"
        f"subprocess.run({expression})\n"
    )
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
@pytest.mark.parametrize("expression", ["CMD", "CMD.split()", "shlex.split(CMD)"])
def test_s10_safe_exec_routes_command_variable_values(tmp_path, expression):
    script = (
        "import shlex\n"
        "from traust_engine._util import safe_exec\n"
        "CMD = 'cargo build'\n"
        f"safe_exec.run({expression})\n"
    )
    assert _s10_failures(tmp_path, script) == []


@pytest.mark.requires_git
@pytest.mark.parametrize("execute", [False, True], ids=["inert-example", "real-build"])
def test_s10_command_variable_docs_and_routed_example_are_not_blanket_exemptions(tmp_path, execute):
    script = '''"""Example: cargo build or go build ./..."""
import shlex
import subprocess
from traust_engine._util import safe_exec

CMD = "cargo build"
print(CMD)
subprocess.run(["echo", CMD])
safe_exec.run(CMD.split())
'''
    if execute:
        script += "subprocess.run(shlex.split(CMD))\n"
    skill = CLEAN_SKILL + "\nExample only: `go build ./...` or `cargo build`.\n"
    assert bool(_s10_failures(tmp_path, script, skill=skill)) is execute


@pytest.mark.requires_git
@pytest.mark.parametrize("variable", [False, True], ids=["literal-argv", "variable-argv"])
@pytest.mark.parametrize(
    "call",
    [
        "subprocess.Popen(COMMAND)",
        "subprocess.check_call(COMMAND)",
        "subprocess.check_output(args=COMMAND)",
        'os.execv("/usr/bin/go", COMMAND)',
        'os.spawnv(os.P_WAIT, "/usr/bin/go", COMMAND)',
    ],
)
def test_s10_command_variables_reach_each_argv_execution_family(tmp_path, variable, call):
    expression = '["go", "build", "./..."]'
    binding = f"COMMAND = {expression}\n" if variable else ""
    invocation = call if variable else call.replace("COMMAND", expression)
    script = f"import os\nimport subprocess\n{binding}{invocation}\n"
    assert _s10_failures(tmp_path, script)


@pytest.mark.requires_git
@pytest.mark.parametrize(
    ("statements", "blocked"),
    [
        (
            'CMD = "cargo build"\nsubprocess.run(normalize(CMD))\n',
            True,
        ),
        (
            'CMD = "go build ./..."\nsubprocess.run(CMD)\nCMD = "echo go build"\n',
            True,
        ),
        (
            'CMD = "go build ./..."\nCMD = "echo go build"\nsubprocess.run(CMD)\n',
            False,
        ),
        (
            'if flag:\n    CMD = "go build ./..."\nelse:\n    CMD = "echo go build"\n'
            "subprocess.run(CMD)\n",
            True,
        ),
        (
            'if flag:\n    CMD = "traust util safe-exec run -- go build ./..."\n'
            'else:\n    CMD = "echo go build"\nsubprocess.run(CMD)\n',
            False,
        ),
        (
            'CMD = "go build ./..."\nsubprocess.run(["echo", unknown, CMD])\n',
            False,
        ),
    ],
)
def test_s10_command_values_keep_execution_order_and_conservative_fallback(
    tmp_path, statements, blocked
):
    script = "import subprocess\n" + statements
    assert bool(_s10_failures(tmp_path, script)) is blocked


@pytest.mark.requires_git
def test_s10_dynamic_command_fallback_does_not_use_inert_examples(tmp_path):
    script = '''"""Example: go build ./..."""
import argparse
import subprocess
from traust_engine._util import safe_exec
print("cargo build")
parser = argparse.ArgumentParser(description="go build ./...")
parser.add_argument("--example", help="cargo build")
safe_exec.run("go build ./...")
subprocess.run(compute_command())
'''
    assert _s10_failures(tmp_path, script) == []
