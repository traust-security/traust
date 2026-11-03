"""Gate regressions for execution-ordered Python command bindings."""

from textwrap import dedent

import pytest

from tests.test_check_skill_security import CLEAN_SKILL, _mk_repo
from traust.cli import check_skill_security as css

pytestmark = pytest.mark.requires_git


def _assert_s10_gate(tmp_path, script, blocked):
    repo = _mk_repo(
        tmp_path,
        skill_md=CLEAN_SKILL,
        script=dedent(script).strip() + "\n",
        script_name="binding_flow.py",
    )
    failures, _ = css.security_failures(repo)
    if blocked:
        assert any(failure.startswith("S10") for failure in failures), failures
    else:
        assert failures == []


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            from subprocess import run as proc
            proc(['go', 'build', './...'])
            from traust_engine._util.safe_exec import run as proc
            """,
            True,
            id="unsafe-call-before-safe-import",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            from subprocess import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="unsafe-call-after-safe-import",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            from subprocess import run as proc
            """,
            False,
            id="unused-later-unsafe-import",
        ),
        pytest.param(
            """
            from subprocess import run as proc
            from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            False,
            id="safe-reimport-before-only-call",
        ),
        pytest.param(
            """
            def worker():
                from subprocess import run as proc
                proc(['go', 'build', './...'])
                from traust_engine._util.safe_exec import run as proc
            """,
            True,
            id="function-unsafe-call-before-safe-import",
        ),
        pytest.param(
            """
            def worker():
                from traust_engine._util.safe_exec import run as proc
                proc(['go', 'build', './...'])
                from subprocess import run as proc
            """,
            False,
            id="function-unused-later-unsafe-import",
        ),
    ],
)
def test_s10_import_bindings_follow_statement_order(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            if condition:
                from subprocess import run as proc
            else:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="if-unsafe-else-safe-merge",
        ),
        pytest.param(
            """
            if condition:
                from traust_engine._util.safe_exec import run as proc
            else:
                from subprocess import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="if-safe-else-unsafe-merge",
        ),
        pytest.param(
            """
            if condition:
                from traust_engine._util.safe_exec import run as proc
            else:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            False,
            id="if-safe-on-every-path",
        ),
        pytest.param(
            """
            if condition:
                from subprocess import run as proc
                proc(['go', 'build', './...'])
            else:
                from traust_engine._util.safe_exec import run as proc
            """,
            True,
            id="unsafe-branch-call-not-routed-by-else-import",
        ),
        pytest.param(
            """
            if condition:
                from traust_engine._util.safe_exec import run as proc
                proc(['go', 'build', './...'])
            else:
                from subprocess import run as proc
            """,
            False,
            id="safe-branch-call-not-tainted-by-else-import",
        ),
        pytest.param(
            """
            from subprocess import run as proc
            if condition:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="if-without-else-retains-unsafe-input",
        ),
        pytest.param(
            """
            try:
                from subprocess import run as proc
            except ImportError:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="try-except-retains-unsafe-success-path",
        ),
        pytest.param(
            """
            try:
                from traust_engine._util.safe_exec import run as proc
            except ImportError:
                from subprocess import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="try-except-retains-unsafe-handler-path",
        ),
        pytest.param(
            """
            try:
                from traust_engine._util.safe_exec import run as proc
            except ImportError:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            False,
            id="try-except-safe-on-every-path",
        ),
        pytest.param(
            """
            try:
                from subprocess import run as proc
                proc(['go', 'build', './...'])
            except ImportError:
                from traust_engine._util.safe_exec import run as proc
            """,
            True,
            id="try-call-not-routed-by-handler-import",
        ),
        pytest.param(
            """
            from subprocess import run as proc
            for item in items:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="for-zero-iterations-retains-unsafe-input",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            for item in items:
                from subprocess import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="for-body-retains-unsafe-output",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            for item in items:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            False,
            id="for-safe-on-every-path",
        ),
        pytest.param(
            """
            from subprocess import run as proc
            while condition:
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="while-zero-iterations-retains-unsafe-input",
        ),
    ],
)
def test_s10_control_flow_keeps_possible_execution_bindings(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            execute = subprocess.getoutput
            execute('go build ./...')
            """,
            True,
            id="getoutput-function-alias",
        ),
        pytest.param(
            """
            import subprocess
            execute = subprocess.run
            execute(['go', 'build', './...'])
            """,
            True,
            id="run-function-alias",
        ),
        pytest.param(
            """
            import subprocess
            execute = subprocess.getoutput
            launch = execute
            launch('go build ./...')
            """,
            True,
            id="transitive-function-alias",
        ),
        pytest.param(
            """
            import subprocess
            execute = launch = subprocess.getoutput
            launch('go build ./...')
            """,
            True,
            id="chained-function-alias",
        ),
        pytest.param(
            """
            import os
            execute = os.system
            execute('go build ./...')
            """,
            True,
            id="os-system-function-alias",
        ),
        pytest.param(
            """
            from traust_engine._util import safe_exec
            execute = safe_exec.run
            launch = execute
            launch(['go', 'build', './...'])
            """,
            False,
            id="routed-safe-exec-function-alias",
        ),
        pytest.param(
            """
            execute = print
            execute('go build ./...')
            """,
            False,
            id="print-function-alias",
        ),
        pytest.param(
            """
            def display(message):
                print(message)
            execute = display
            execute('go build ./...')
            """,
            False,
            id="unrelated-function-alias",
        ),
        pytest.param(
            """
            import subprocess
            execute = subprocess.getoutput
            execute('go build ./...')
            execute = print
            """,
            True,
            id="unsafe-call-before-harmless-reassignment",
        ),
        pytest.param(
            """
            import subprocess
            execute = print
            execute('go build ./...')
            execute = subprocess.getoutput
            """,
            False,
            id="harmless-call-before-unused-unsafe-reassignment",
        ),
        pytest.param(
            """
            import subprocess
            execute = subprocess.getoutput
            execute = print
            execute('go build ./...')
            """,
            False,
            id="harmless-reassignment-before-only-call",
        ),
        pytest.param(
            """
            import subprocess
            execute = print
            execute = subprocess.getoutput
            execute('go build ./...')
            """,
            True,
            id="unsafe-reassignment-before-call",
        ),
        pytest.param(
            """
            import subprocess
            execute = subprocess.getoutput
            launch = execute
            execute = print
            launch('go build ./...')
            """,
            True,
            id="copied-alias-survives-original-reassignment",
        ),
        pytest.param(
            """
            import subprocess
            if condition:
                execute = subprocess.getoutput
            else:
                execute = print
            execute('go build ./...')
            """,
            True,
            id="function-alias-branch-merge",
        ),
    ],
)
def test_s10_function_value_aliases_follow_assignments(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            from subprocess import *
            run(['go', 'build', './...'])
            """,
            True,
            id="subprocess-wildcard-run",
        ),
        pytest.param(
            """
            from subprocess import *
            getoutput('go build ./...')
            """,
            True,
            id="subprocess-wildcard-getoutput",
        ),
        pytest.param(
            """
            from subprocess import *
            run(['traust', 'util', 'safe-exec', 'run', '--', 'go', 'build', './...'])
            """,
            False,
            id="subprocess-wildcard-explicit-routed-command",
        ),
        pytest.param(
            """
            from subprocess import *
            from traust_engine._util.safe_exec import run
            run(['go', 'build', './...'])
            """,
            False,
            id="explicit-safe-import-overrides-wildcard",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            from subprocess import *
            run(['go', 'build', './...'])
            """,
            True,
            id="wildcard-overrides-earlier-safe-import",
        ),
        pytest.param(
            """
            from subprocess import *
            execute = getoutput
            execute('go build ./...')
            """,
            True,
            id="subprocess-wildcard-function-alias",
        ),
    ],
)
def test_s10_wildcard_imports_bind_execution_functions(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            from subprocess import run as proc
            def example():
                from traust_engine._util.safe_exec import run as proc
            def worker():
                proc(['go', 'build', './...'])
            """,
            True,
            id="sibling-safe-import-cannot-route-worker",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            def example():
                from subprocess import run as proc
            def worker():
                proc(['go', 'build', './...'])
            """,
            False,
            id="sibling-unsafe-import-cannot-taint-worker",
        ),
        pytest.param(
            """
            def outer():
                from subprocess import run as proc
                def example():
                    from traust_engine._util.safe_exec import run as proc
                def worker():
                    proc(['go', 'build', './...'])
            """,
            True,
            id="nested-sibling-safe-import-cannot-route-worker",
        ),
        pytest.param(
            """
            def outer():
                from traust_engine._util.safe_exec import run as proc
                def example():
                    from subprocess import run as proc
                def worker():
                    proc(['go', 'build', './...'])
            """,
            False,
            id="nested-sibling-unsafe-import-cannot-taint-worker",
        ),
        pytest.param(
            """
            from subprocess import run as proc
            def example():
                from traust_engine._util.safe_exec import run as proc
            proc(['go', 'build', './...'])
            """,
            True,
            id="nested-safe-import-cannot-route-module-call",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            def example():
                from subprocess import run as proc
            proc(['go', 'build', './...'])
            """,
            False,
            id="nested-unsafe-import-cannot-taint-module-call",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run as proc
            def worker():
                global proc
                from subprocess import run as proc
                proc(['go', 'build', './...'])
            """,
            True,
            id="global-declaration-local-unsafe-rebinding",
        ),
        pytest.param(
            """
            from subprocess import run as proc
            def worker():
                global proc
                from traust_engine._util.safe_exec import run as proc
                proc(['go', 'build', './...'])
            """,
            False,
            id="global-declaration-local-safe-rebinding",
        ),
        pytest.param(
            """
            def outer():
                from traust_engine._util.safe_exec import run as proc
                def worker():
                    nonlocal proc
                    from subprocess import run as proc
                    proc(['go', 'build', './...'])
            """,
            True,
            id="nonlocal-declaration-local-unsafe-rebinding",
        ),
        pytest.param(
            """
            def outer():
                from subprocess import run as proc
                def worker():
                    nonlocal proc
                    from traust_engine._util.safe_exec import run as proc
                    proc(['go', 'build', './...'])
            """,
            False,
            id="nonlocal-declaration-local-safe-rebinding",
        ),
    ],
)
def test_s10_lexical_bindings_do_not_leak_between_scopes(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)
