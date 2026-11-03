"""Gate regressions for control-flow-dependent Python execution bindings."""

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
        script_name="control_flow.py",
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
            import subprocess
            proc = subprocess.run
            True or (proc := print)
            proc(['go', 'build'])
            """,
            True,
            id="true-or-skips-safe-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            False and (proc := print)
            proc(['go', 'build'])
            """,
            True,
            id="false-and-skips-safe-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            condition or (proc := print)
            proc(['go', 'build'])
            """,
            True,
            id="unknown-or-preserves-unsafe-path",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            condition and (proc := print)
            proc(['go', 'build'])
            """,
            True,
            id="unknown-and-preserves-unsafe-path",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            condition and (proc := subprocess.run)
            proc(['go', 'build'])
            """,
            True,
            id="unknown-and-can-rebind-unsafe",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            True and (proc := print)
            proc(['go', 'build'])
            """,
            False,
            id="true-and-performs-safe-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            False or (proc := print)
            proc(['go', 'build'])
            """,
            False,
            id="false-or-performs-safe-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            True or (proc := subprocess.run)
            False and (proc := subprocess.run)
            proc(['go', 'build'])
            """,
            False,
            id="skipped-unsafe-rebindings-stay-benign",
        ),
        pytest.param(
            """
            proc = print
            condition or (proc := print)
            proc(['go', 'build'])
            """,
            False,
            id="unknown-short-circuit-all-benign",
        ),
    ],
)
def test_s10_short_circuit_bindings_follow_reachable_operands(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            proc = print
            for item in range(1):
                proc = subprocess.run
                break
                proc = print
            proc(['go', 'build'])
            """,
            True,
            id="break-keeps-binding-before-unreachable-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            for item in range(1):
                proc = subprocess.run
                continue
                proc = print
            proc(['go', 'build'])
            """,
            True,
            id="continue-keeps-binding-before-unreachable-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            def build(stop):
                proc = subprocess.run
                if stop:
                    return
                    proc = print
                proc(['go', 'build'])
            build(False)
            """,
            True,
            id="return-branch-cannot-clobber-fallthrough-binding",
        ),
        pytest.param(
            """
            import subprocess
            def build():
                proc = subprocess.run
                proc(['go', 'build'])
                return
                proc = print
            build()
            """,
            True,
            id="return-cannot-retroactively-route-earlier-call",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            for item in range(1):
                break
                proc = subprocess.run
            proc(['go', 'build'])
            """,
            False,
            id="break-skips-unsafe-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            for item in range(1):
                continue
                proc = subprocess.run
            proc(['go', 'build'])
            """,
            False,
            id="continue-skips-unsafe-rebinding",
        ),
        pytest.param(
            """
            import subprocess
            def build():
                proc = print
                return
                proc = subprocess.run
                proc(['go', 'build'])
            build()
            """,
            False,
            id="return-skips-unreachable-execution",
        ),
    ],
)
def test_s10_control_exits_preserve_only_reachable_bindings(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            a = b = c = print
            for item in range(3):
                a = b
                b = c
                c = subprocess.run
            a(['go', 'build'])
            """,
            True,
            id="unsafe-alias-reaches-output-after-three-iterations",
        ),
        pytest.param(
            """
            import subprocess
            a = b = c = print
            for item in range(3):
                a = b
                b = c
                c = subprocess.run
                a(['go', 'build'])
            """,
            True,
            id="unsafe-alias-reaches-call-in-later-iteration",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            a = b = c = print
            for item in range(3):
                a = b
                b = c
                c = run
            a(['go', 'build'])
            """,
            False,
            id="every-iteration-keeps-only-benign-or-routed-aliases",
        ),
    ],
)
def test_s10_loop_bindings_reach_a_fixed_point(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            proc = print
            while proc(['go', 'build']) is None:
                proc = subprocess.run
            """,
            True,
            id="second-while-test-executes-rebound-unsafe-callable",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            while proc(['go', 'build']) is None:
                proc = print
            """,
            True,
            id="first-while-test-is-not-retroactively-routed",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            proc = print
            while proc(['go', 'build']) is None:
                proc = run
            """,
            False,
            id="repeated-while-tests-only-print-or-use-safe-exec",
        ),
    ],
)
def test_s10_while_tests_use_loop_carried_bindings(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            proc = print
            class C:
                global proc
                proc = subprocess.run
            proc(['go', 'build'])
            """,
            True,
            id="class-global-rebinding-affects-module-call",
        ),
        pytest.param(
            """
            import subprocess
            def build():
                proc = print
                class C:
                    nonlocal proc
                    proc = subprocess.run
                proc(['go', 'build'])
            build()
            """,
            True,
            id="class-nonlocal-rebinding-affects-enclosing-call",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            class C:
                global proc
                proc = print
            proc(['go', 'build'])
            """,
            False,
            id="class-global-benign-rebinding-takes-effect-immediately",
        ),
        pytest.param(
            """
            import subprocess
            def build():
                proc = subprocess.run
                class C:
                    nonlocal proc
                    proc = print
                proc(['go', 'build'])
            build()
            """,
            False,
            id="class-nonlocal-benign-rebinding-takes-effect-immediately",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            class C:
                proc = subprocess.run
            proc(['go', 'build'])
            """,
            False,
            id="class-local-rebinding-does-not-escape",
        ),
    ],
)
def test_s10_class_bodies_apply_declared_outer_binding_effects(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            proc = print
            generator = (proc(['go', 'build']) for item in range(1))
            proc = subprocess.run
            list(generator)
            """,
            True,
            id="generator-uses-unsafe-binding-at-consumption",
        ),
        pytest.param(
            """
            proc = print
            generator = (proc(['go', 'build']) for item in range(1))
            list(generator)
            """,
            False,
            id="generator-with-benign-captured-callable",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            proc = print
            generator = (proc(['go', 'build']) for item in range(1))
            proc = run
            list(generator)
            """,
            False,
            id="generator-rebound-to-safe-exec-before-consumption",
        ),
        pytest.param(
            """
            import subprocess
            proc = print
            values = [proc(['go', 'build']) for item in range(1)]
            proc = subprocess.run
            """,
            False,
            id="eager-comprehension-does-not-use-later-rebinding",
        ),
    ],
)
def test_s10_generators_use_deferred_callable_bindings(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            proc = print
            values = [(proc := subprocess.run) for item in range(1)]
            proc(['go', 'build'])
            """,
            True,
            id="comprehension-walrus-updates-module-binding",
        ),
        pytest.param(
            """
            import subprocess
            def build():
                proc = print
                values = [(proc := subprocess.run) for item in range(1)]
                proc(['go', 'build'])
            build()
            """,
            True,
            id="comprehension-walrus-updates-enclosing-function-binding",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            proc = print
            values = [(proc := run) for item in range(1)]
            proc(['go', 'build'])
            """,
            False,
            id="comprehension-walrus-only-introduces-safe-exec",
        ),
        pytest.param(
            """
            proc = print
            values = [(proc := print) for item in range(1)]
            proc(['go', 'build'])
            """,
            False,
            id="comprehension-walrus-keeps-benign-callable",
        ),
    ],
)
def test_s10_comprehension_walrus_updates_containing_scope(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            proc, = (subprocess.run,)
            proc(['go', 'build'])
            """,
            True,
            id="singleton-tuple-unpacks-unsafe-callable",
        ),
        pytest.param(
            """
            import subprocess
            display, proc = (print, subprocess.run)
            proc(['go', 'build'])
            """,
            True,
            id="second-tuple-position-is-unsafe",
        ),
        pytest.param(
            """
            import subprocess
            proc, display = (print, subprocess.run)
            proc(['go', 'build'])
            """,
            False,
            id="first-tuple-position-is-benign-despite-unsafe-neighbor",
        ),
        pytest.param(
            """
            import subprocess
            display, proc = (subprocess.run, print)
            proc(['go', 'build'])
            """,
            False,
            id="second-tuple-position-is-benign-despite-unsafe-neighbor",
        ),
    ],
)
def test_s10_tuple_unpacking_preserves_callable_positions(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            def build(proc=subprocess.run):
                proc(['go', 'build'])
            build()
            """,
            True,
            id="unsafe-callable-default-executes-build",
        ),
        pytest.param(
            """
            import subprocess
            proc = subprocess.run
            def build(execute=proc):
                execute(['go', 'build'])
            proc = print
            build()
            """,
            True,
            id="callable-default-captures-definition-time-binding",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            def build(proc=run):
                proc(['go', 'build'])
            build()
            """,
            False,
            id="safe-exec-callable-default-routes-build",
        ),
        pytest.param(
            """
            def build(proc=print):
                proc(['go', 'build'])
            build()
            """,
            False,
            id="benign-callable-default-does-not-execute-build",
        ),
    ],
)
def test_s10_function_defaults_preserve_callable_provenance(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize(
    ("script", "blocked"),
    [
        pytest.param(
            """
            import subprocess
            match subprocess.run:
                case proc:
                    pass
            proc(['go', 'build'])
            """,
            True,
            id="match-capture-binds-unsafe-callable",
        ),
        pytest.param(
            """
            match print:
                case proc:
                    pass
            proc(['go', 'build'])
            """,
            False,
            id="match-capture-binds-benign-callable",
        ),
        pytest.param(
            """
            from traust_engine._util.safe_exec import run
            match run:
                case proc:
                    pass
            proc(['go', 'build'])
            """,
            False,
            id="match-capture-binds-safe-exec-callable",
        ),
    ],
)
def test_s10_match_captures_preserve_subject_bindings(tmp_path, script, blocked):
    _assert_s10_gate(tmp_path, script, blocked)


@pytest.mark.parametrize("unsafe", [False, True], ids=["report-only", "unsafe-callback"])
def test_s10_deferred_walrus_keeps_input_closure_immutable(tmp_path, unsafe):
    callback = "subprocess.run" if unsafe else "print"
    script = f"""
        import subprocess
        def render(items):
            callback = None
            return (callback(['go', 'build']) for item in items
                    if (callback := {callback}))
        render([1])
    """
    _assert_s10_gate(tmp_path, script, unsafe)


@pytest.mark.parametrize(
    ("execution", "blocked"),
    [
        ("subprocess.run(compute_command())", False),
        ("subprocess.run(['echo', 'ok'])", False),
        ("subprocess.run(report)", True),
        ("subprocess.run(identity(report))", True),
    ],
    ids=[
        "unrelated-unresolved-command",
        "unrelated-harmless-command",
        "executed-cap",
        "executed-cap-provenance",
    ],
)
def test_s10_capped_report_data_requires_execution_provenance(tmp_path, execution, blocked):
    script = f"""
        import subprocess
        def identity(value):
            return value
        def compute_command():
            return ['echo', 'ok']
        report = ['report field']
        for item in items:
            report = report + ['report field']
        {execution}
    """
    _assert_s10_gate(tmp_path, script, blocked)
