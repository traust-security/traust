"""Starred call arguments retain possible positions and executable provenance."""

import pytest

from tests.test_s10_callable_boundaries import _assert_gate

pytestmark = pytest.mark.requires_git


@pytest.mark.parametrize(
    ("setup", "call", "blocked"),
    [
        pytest.param(
            'values = ["go build ./...", "go build ./..."]\n',
            "command(*iter(values))",
            True,
            id="reported-second-parameter-bypass",
        ),
        pytest.param(
            'values = ["echo first", "echo ok"]\n',
            "command(*iter(values))",
            False,
            id="unknown-span-harmless-values",
        ),
        pytest.param(
            'values = ["go build ./...", "echo ok"]\n',
            "command(*values)",
            False,
            id="known-length-retains-element-position",
        ),
        pytest.param("", "command(*())", False, id="known-empty-keeps-default"),
        pytest.param(
            'def cursor(values):\n    return iter(values)\nvalues = ["first", "go build ./..."]\n',
            "command(*cursor(values))",
            True,
            id="opaque-local-iterator-is-not-special-cased",
        ),
        pytest.param(
            'values = ["go build ./..."]\n',
            'command(*iter(values), "echo ok")',
            False,
            id="trailing-fixed-argument-limits-valid-star-positions",
        ),
        pytest.param(
            'values = ["prefix"]\n',
            'command(*iter(values), "go build ./...")',
            True,
            id="trailing-fixed-command-can-reach-second-parameter",
        ),
        pytest.param(
            'values = ["go build ./..."]\n',
            'command(*iter(values), text="echo ok")',
            False,
            id="keyword-binding-excludes-duplicate-positional-paths",
        ),
        pytest.param(
            "def cursor(values):\n    return iter(values)\n"
            'values = ("prefix",) if flag else cursor(("prefix", "go build ./..."))\n',
            "command(*values)",
            True,
            id="known-elements-do-not-erase-unknown-length-alternative",
        ),
        pytest.param(
            'values = ["prefix"]\n',
            'command(*iter(values), *iter(["go build ./..."]))',
            True,
            id="multiple-unknown-spans",
        ),
    ],
)
def test_starred_span_binds_every_possible_positional_parameter(tmp_path, setup, call, blocked):
    _assert_gate(
        tmp_path,
        setup
        + 'def command(prefix="echo ok", text="echo ok"):\n    return text\n'
        + f"subprocess.run({call}, shell=True)\n",
        blocked,
    )


@pytest.mark.parametrize(
    ("definition", "call", "blocked"),
    [
        pytest.param(
            'def command(prefix="echo ok", text="echo ok"):\n    return prefix\n',
            'command("echo ok", *iter(["go build ./..."]))',
            False,
            id="fixed-prefix-does-not-inherit-starred-data",
        ),
        pytest.param(
            'def command(*parts, text="echo ok"):\n    return text\n',
            'command(*iter(["go build ./..."]))',
            False,
            id="star-cannot-fill-keyword-only-parameter",
        ),
        pytest.param(
            "def command(*parts):\n    return parts[1]\n",
            'command(*iter(["prefix", "go build ./..."]))',
            True,
            id="variadic-element-retains-command-source",
        ),
        pytest.param(
            "def command(*parts):\n    return parts[1]\n",
            'command(*iter(["echo prefix", "echo ok"]))',
            False,
            id="variadic-harmless-elements",
        ),
        pytest.param(
            'def command(prefix="echo ok", text="echo ok"):\n    return text\n'
            "def forward(*parts):\n    return command(*parts)\n",
            'forward(*iter(["prefix", "go build ./..."]))',
            True,
            id="variadic-forwarding-keeps-unknown-span",
        ),
        pytest.param(
            'def command(prefix="echo ok", text="echo ok"):\n    return text\n'
            "def forward(*parts):\n    return command(*parts)\n",
            'forward(*iter(["echo prefix", "echo ok"]))',
            False,
            id="variadic-forwarding-harmless-control",
        ),
        pytest.param(
            "class Commands:\n"
            '    def command(self, prefix="echo ok", text="echo ok"):\n'
            "        return text\n"
            "command = Commands().command\n",
            'command(*iter(["prefix", "go build ./..."]))',
            True,
            id="bound-method-receiver-keeps-fixed-position",
        ),
        pytest.param(
            "import shlex\ndef command(*parts):\n    return parts[1]\n",
            """command(*shlex.split("prefix 'go build ./...'"))""",
            True,
            id="argv-only-iterator-elements-remain-scalar-sources",
        ),
        pytest.param(
            "import shlex\ndef command(*parts):\n    return parts[1]\n",
            """command(*shlex.split("prefix 'echo ok'"))""",
            False,
            id="argv-only-iterator-harmless-scalar-source",
        ),
    ],
)
def test_starred_argument_scope_and_forwarding(tmp_path, definition, call, blocked):
    _assert_gate(tmp_path, definition + f"subprocess.run({call}, shell=True)\n", blocked)


@pytest.mark.parametrize("awaited,blocked", [(False, False), (True, True)])
def test_starred_arguments_survive_suspended_coroutine_binding(tmp_path, awaited, blocked):
    prefix = "await " if awaited else ""
    _assert_gate(
        tmp_path,
        'async def command(prefix="echo ok", text="echo ok"):\n    return text\n'
        "async def execute():\n"
        f'    subprocess.run({prefix}command(*iter(["prefix", "go build ./..."])), shell=True)\n',
        blocked,
    )


@pytest.mark.parametrize("sink,blocked", [("subprocess.run", True), ("safe_exec.run", False)])
def test_direct_starred_command_keeps_execution_routing(tmp_path, sink, blocked):
    shell = ", shell=True" if sink == "subprocess.run" else ""
    _assert_gate(tmp_path, f'{sink}(*iter(["go build ./..."]){shell})\n', blocked)
