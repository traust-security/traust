"""Returned command sources reach sinks without sweeping unrelated child scopes."""

from textwrap import dedent

import pytest

from tests.test_check_skill_security import CLEAN_SKILL, _mk_repo
from traust.cli import check_skill_security as css

pytestmark = pytest.mark.requires_git


def _assert_gate(tmp_path, script, blocked):
    repo = _mk_repo(
        tmp_path, skill_md=CLEAN_SKILL, script=dedent(script), script_name="return_source.py"
    )
    failures, _ = css.security_failures(repo)
    assert any(failure.startswith("S10") for failure in failures) is blocked, failures


def test_zero_argument_helper_return_reaches_shell_execution(tmp_path):
    _assert_gate(
        tmp_path,
        """\
        import subprocess
        def command():
            cmd = 'go build ./...'
            return cmd
        subprocess.run(command(), shell=True)
        """,
        True,
    )


@pytest.mark.parametrize(
    ("body", "sink", "blocked"),
    [
        pytest.param(
            'def command():\n    return "cargo build"\n',
            "subprocess.run(command())\n",
            True,
            id="literal-return",
        ),
        pytest.param(
            'def command():\n    return ["go", "build", "./..."]\n',
            "subprocess.run(command())\n",
            True,
            id="argv-return",
        ),
        pytest.param(
            'def command():\n    return ["echo", "go build ./..."]\n',
            "subprocess.run(command())\n",
            False,
            id="argv-data-return",
        ),
        pytest.param(
            'def command():\n    return "echo go build ./..."\n',
            "subprocess.run(command(), shell=True)\n",
            False,
            id="harmless-shell-return",
        ),
        pytest.param(
            'def command():\n    cmd = "go build ./..."\n',
            "subprocess.run(command(), shell=True)\n",
            False,
            id="unreturned-child-value",
        ),
        pytest.param(
            'def unused():\n    return "go build ./..."\ndef command():\n    return "echo ok"\n',
            "subprocess.run(command(), shell=True)\n",
            False,
            id="unrelated-child-helper",
        ),
        pytest.param(
            'def command():\n    return "echo ok"\n'
            'def unrelated():\n    def command():\n        return "go build ./..."\n',
            "subprocess.run(command(), shell=True)\n",
            False,
            id="same-name-child-does-not-leak",
        ),
        pytest.param(
            'def command():\n    return "go build ./..."\n'
            'def unrelated():\n    def command():\n        return "echo ok"\n',
            "subprocess.run(command(), shell=True)\n",
            True,
            id="same-name-child-does-not-hide",
        ),
        pytest.param(
            'def command():\n    return "go build ./..."\nalias = command\n',
            "subprocess.run(alias(), shell=True)\n",
            True,
            id="callable-alias-return",
        ),
        pytest.param(
            'def inner():\n    return "go build ./..."\ndef command():\n    return inner()\n',
            "subprocess.run(command(), shell=True)\n",
            True,
            id="helper-chain",
        ),
        pytest.param(
            'command = lambda: "go build ./..."\n',
            "subprocess.run(command(), shell=True)\n",
            True,
            id="lambda-return",
        ),
        pytest.param(
            'def command():\n    def inner():\n        cmd = "go build ./..."\n'
            "        return cmd\n    return inner()\n",
            "subprocess.run(command(), shell=True)\n",
            True,
            id="nested-return-chain",
        ),
        pytest.param(
            'def command():\n    if flag:\n        return "go build ./..."\n    return "echo ok"\n',
            "subprocess.run(command(), shell=True)\n",
            True,
            id="conditional-return",
        ),
        pytest.param(
            'def command():\n    cmd = "go build ./..."\n    cmd = "echo ok"\n    return cmd\n',
            "subprocess.run(command(), shell=True)\n",
            False,
            id="overwritten-child-command",
        ),
        pytest.param(
            'def command():\n    try:\n        return "go build ./..."\n'
            '    finally:\n        return "echo ok"\n',
            "subprocess.run(command(), shell=True)\n",
            False,
            id="finally-overrides-return",
        ),
        pytest.param(
            'def command():\n    try:\n        return "go build ./..."\n'
            "    finally:\n        pass\n",
            "subprocess.run(command(), shell=True)\n",
            True,
            id="finally-retains-return",
        ),
        pytest.param(
            'def command():\n    if flag:\n        return "go build ./..."\n    return command()\n',
            "subprocess.run(command(), shell=True)\n",
            True,
            id="recursive-return-provenance",
        ),
        pytest.param(
            'def command():\n    return "go build ./..."\n',
            'print(command())\nsubprocess.run(["echo", "ok"])\n',
            False,
            id="returned-print-data",
        ),
        pytest.param(
            'def command():\n    return "go build ./..."\n',
            "safe_exec.run(command())\nsubprocess.run(compute_command())\n",
            False,
            id="returned-routed-data-does-not-taint-unknown-sink",
        ),
    ],
)
def test_local_callable_return_provenance(tmp_path, body, sink, blocked):
    script = "import subprocess\nfrom traust_engine._util import safe_exec\n" + body + sink
    _assert_gate(tmp_path, script, blocked)
