"""S10 follows effective local callables without confusing data with execution."""

from textwrap import dedent

import pytest

from tests.test_check_skill_security import CLEAN_SKILL, _mk_repo
from traust.cli import check_skill_security as css

pytestmark = pytest.mark.requires_git


def _assert_gate(tmp_path, script, blocked):
    repo = _mk_repo(
        tmp_path,
        skill_md=CLEAN_SKILL,
        script=("import subprocess\nfrom traust_engine._util import safe_exec\n" + dedent(script)),
        script_name="callable_boundary.py",
    )
    failures, _ = css.security_failures(repo)
    assert any(failure.startswith("S10") for failure in failures) is blocked, failures


@pytest.mark.parametrize(
    ("original", "replacement", "blocked"),
    [
        pytest.param("go build ./...", "echo ok", False, id="harmless-replacement"),
        pytest.param("echo ok", "go build ./...", True, id="unsafe-replacement"),
    ],
)
def test_local_decorator_replaces_original_return(tmp_path, original, replacement, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def replace(original):
            def command():
                return {replacement!r}
            return command
        @replace
        def command():
            return {original!r}
        subprocess.run(command(), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    "decorator",
    [
        pytest.param(
            "def decorate(function):\n    return function\n",
            id="identity",
        ),
        pytest.param(
            "def decorate(function):\n"
            "    def command():\n"
            "        return function()\n"
            "    return command\n",
            id="closure-forwarding",
        ),
        pytest.param(
            "def factory():\n"
            "    def decorate(function):\n"
            "        def command():\n"
            "            return function()\n"
            "        return command\n"
            "    return decorate\n"
            "decorate = factory()\n",
            id="factory-forwarding",
        ),
    ],
)
@pytest.mark.parametrize(
    ("returned", "blocked"),
    [
        pytest.param("go build ./...", True, id="command"),
        pytest.param("echo ok", False, id="harmless"),
    ],
)
def test_identity_and_closure_decorators(tmp_path, decorator, returned, blocked):
    _assert_gate(
        tmp_path,
        decorator
        + dedent(
            f"""\
            @decorate
            def command():
                return {returned!r}
            subprocess.run(command(), shell=True)
            """
        ),
        blocked,
    )


@pytest.mark.parametrize(
    ("outer", "inner", "blocked"),
    [
        pytest.param("harmless", "unsafe", False, id="outer-harmless-wins"),
        pytest.param("unsafe", "harmless", True, id="outer-unsafe-wins"),
    ],
)
def test_local_decorator_stack_applies_bottom_up(tmp_path, outer, inner, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def harmless(function):
            def wrapper():
                return "echo ok"
            return wrapper
        def unsafe(function):
            def wrapper():
                return "go build ./..."
            return wrapper
        @{outer}
        @{inner}
        def command():
            return "echo original"
        subprocess.run(command(), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("executed", "routed", "blocked"),
    [
        pytest.param("harmless", "unsafe", False, id="unsafe-context-does-not-leak"),
        pytest.param("unsafe", "harmless", True, id="harmless-context-does-not-hide"),
    ],
)
def test_decorator_factory_retains_each_closure(tmp_path, executed, routed, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def replace(text):
            def decorate(function):
                def wrapper():
                    return text
                return wrapper
            return decorate
        @replace("go build ./...")
        def unsafe():
            return "echo original"
        @replace("echo ok")
        def harmless():
            return "go build ./..."
        safe_exec.run({routed}())
        subprocess.run({executed}(), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize("name", ["staticmethod", "classmethod"])
def test_shadowed_descriptor_name_is_a_local_decorator(tmp_path, name):
    _assert_gate(
        tmp_path,
        f"""\
        def {name}(function):
            def wrapper():
                return "echo ok"
            return wrapper
        @{name}
        def command():
            return "go build ./..."
        subprocess.run(command(), shell=True)
        """,
        False,
    )


@pytest.mark.parametrize(
    ("decoration", "parameters", "receiver"),
    [
        pytest.param("", "self", "Commands()", id="instance-method"),
        pytest.param("    @staticmethod\n", "", "Commands", id="static-on-class"),
        pytest.param("    @staticmethod\n", "", "Commands()", id="static-on-instance"),
        pytest.param("    @classmethod\n", "cls", "Commands", id="class-on-class"),
        pytest.param("    @classmethod\n", "cls", "Commands()", id="class-on-instance"),
    ],
)
def test_local_methods_return_commands(tmp_path, decoration, parameters, receiver):
    _assert_gate(
        tmp_path,
        "class Commands:\n"
        + decoration
        + f"    def command({parameters}):\n"
        + '        return ["go", "build", "./..."]\n'
        + f"subprocess.run({receiver}.command())\n",
        True,
    )


@pytest.mark.parametrize(
    ("decoration", "parameters"),
    [
        pytest.param("", "self", id="instance-method"),
        pytest.param("    @staticmethod\n", "", id="static-method"),
        pytest.param("    @classmethod\n", "cls", id="class-method"),
    ],
)
@pytest.mark.parametrize(
    ("returned", "sink", "blocked"),
    [
        pytest.param(
            '["echo", "go build ./..."]',
            "subprocess.run(alias())",
            False,
            id="argv-data-alias",
        ),
        pytest.param(
            '"go build ./..."',
            "subprocess.run(alias(), shell=True)",
            True,
            id="command-alias",
        ),
        pytest.param(
            '"go build ./..."',
            "safe_exec.run(alias())",
            False,
            id="routed-alias",
        ),
    ],
)
def test_local_method_aliases_preserve_return_kind(
    tmp_path, decoration, parameters, returned, sink, blocked
):
    _assert_gate(
        tmp_path,
        "class Commands:\n"
        + decoration
        + f"    def command({parameters}):\n"
        + f"        return {returned}\n"
        + "alias = Commands().command\n"
        + sink
        + "\n",
        blocked,
    )


@pytest.mark.parametrize(
    ("decoration", "parameter", "receiver"),
    [
        pytest.param("", "self", "Commands()", id="instance-receiver"),
        pytest.param("    @classmethod\n", "cls", "Commands", id="class-receiver"),
    ],
)
def test_local_method_receiver_resolves_explicit_class_data(
    tmp_path, decoration, parameter, receiver
):
    _assert_gate(
        tmp_path,
        "class Commands:\n"
        '    text = "go build ./..."\n'
        + decoration
        + f"    def command({parameter}):\n"
        + f"        return {parameter}.text\n"
        + f"subprocess.run({receiver}.command(), shell=True)\n",
        True,
    )


@pytest.mark.parametrize(
    ("executed", "routed", "blocked"),
    [
        pytest.param("Harmless", "Unsafe", False, id="same-name-method-does-not-leak"),
        pytest.param("Unsafe", "Harmless", True, id="same-name-method-does-not-hide"),
    ],
)
def test_method_definition_identity_separates_classes(tmp_path, executed, routed, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        class Unsafe:
            def command(self):
                return "go build ./..."
        class Harmless:
            def command(self):
                return "echo ok"
        safe_exec.run({routed}().command())
        subprocess.run({executed}().command(), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("assignment", "sink", "blocked"),
    [
        pytest.param(
            "holder.command = unsafe\n",
            "subprocess.run(holder.command(), shell=True)\n",
            True,
            id="explicit-instance-callable",
        ),
        pytest.param(
            "holder.command = unsafe\nholder.command = harmless\n",
            "subprocess.run(holder.command(), shell=True)\n",
            False,
            id="instance-callable-rebound",
        ),
        pytest.param(
            "holder.command = unsafe\nalias = holder.command\nholder.command = harmless\n",
            "subprocess.run(alias(), shell=True)\n",
            True,
            id="attribute-alias-survives-rebinding",
        ),
    ],
)
def test_explicit_local_callable_attributes(tmp_path, assignment, sink, blocked):
    _assert_gate(
        tmp_path,
        dedent(
            """\
            def unsafe():
                return "go build ./..."
            def harmless():
                return "echo ok"
            class Holder:
                pass
            holder = Holder()
            """
        )
        + assignment
        + sink,
        blocked,
    )


@pytest.mark.parametrize(
    ("body", "sink", "blocked"),
    [
        pytest.param(
            'async def command():\n    return "go build ./..."\n',
            "subprocess.run(command(), shell=True)",
            False,
            id="unawaited-coroutine-is-not-command",
        ),
        pytest.param(
            'async def command():\n    return "go build ./..."\n'
            "pending = command()\nalias = pending\n",
            "subprocess.run(alias, shell=True)",
            False,
            id="unawaited-coroutine-alias-is-not-command",
        ),
        pytest.param(
            'async def command():\n    return "go build ./..."\n'
            "def wrapper():\n    return command()\n",
            "subprocess.run(wrapper(), shell=True)",
            False,
            id="ordinary-wrapper-returns-coroutine-not-body-return",
        ),
        pytest.param(
            'async def command():\n    return "go build ./..."\n',
            "subprocess.run(await command(), shell=True)",
            True,
            id="awaited-command",
        ),
        pytest.param(
            'async def command():\n    return ["echo", "go build ./..."]\n',
            "subprocess.run(await command())",
            False,
            id="awaited-argv-data",
        ),
        pytest.param(
            'async def command():\n    return "echo go build ./..."\n',
            "subprocess.run(await command(), shell=True)",
            False,
            id="awaited-harmless-shell",
        ),
        pytest.param(
            'async def command():\n    return "go build ./..."\n',
            "safe_exec.run(await command())",
            False,
            id="awaited-routed-command",
        ),
        pytest.param(
            'async def command():\n    return ["go", "build", "./..."]\npending = command()\n',
            "subprocess.run(await pending)",
            True,
            id="awaited-coroutine-value-alias",
        ),
    ],
)
def test_coroutine_return_requires_await(tmp_path, body, sink, blocked):
    _assert_gate(
        tmp_path,
        "import asyncio\n" + body + "async def main():\n    " + sink + "\nasyncio.run(main())\n",
        blocked,
    )


@pytest.mark.parametrize(
    ("executed", "routed", "blocked"),
    [
        pytest.param("echo ok", "go build ./...", False, id="unsafe-await-does-not-leak"),
        pytest.param("go build ./...", "echo ok", True, id="harmless-await-does-not-hide"),
    ],
)
def test_same_coroutine_definition_keeps_call_arguments_separate(
    tmp_path, executed, routed, blocked
):
    _assert_gate(
        tmp_path,
        f"""\
        import asyncio
        async def command(text):
            return text
        async def main():
            safe_exec.run(await command({routed!r}))
            subprocess.run(await command({executed!r}), shell=True)
        asyncio.run(main())
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("body", "blocked"),
    [
        pytest.param(
            'def command():\n    yield "marker"\n    return "go build ./..."\n',
            False,
            id="generator-return-is-not-call-result",
        ),
        pytest.param(
            'def command():\n    if False:\n        yield "marker"\n    return "go build ./..."\n',
            False,
            id="unreachable-yield-still-makes-generator",
        ),
        pytest.param(
            'def command():\n    yield from ()\n    return "go build ./..."\n',
            False,
            id="yield-from-makes-generator",
        ),
        pytest.param(
            'def command():\n    def nested():\n        yield "marker"\n'
            '    return "go build ./..."\n',
            True,
            id="nested-generator-does-not-reclassify-outer",
        ),
        pytest.param(
            'def command():\n    async def nested():\n        yield "marker"\n'
            '    return "go build ./..."\n',
            True,
            id="nested-async-generator-does-not-reclassify-outer",
        ),
        pytest.param(
            'def generate():\n    yield "marker"\n    return "go build ./..."\n'
            "def command():\n    return generate()\n",
            False,
            id="ordinary-wrapper-returns-generator-object",
        ),
    ],
)
def test_generator_kind_belongs_to_its_own_definition(tmp_path, body, blocked):
    _assert_gate(
        tmp_path,
        body + "subprocess.run(command(), shell=True)\n",
        blocked,
    )


@pytest.mark.parametrize(
    ("prepare", "sink", "blocked"),
    [
        pytest.param(
            'async def prepare():\n    holder.text = "echo ok"\n',
            "pending = prepare()\nsubprocess.run(holder.text, shell=True)\n",
            True,
            id="unawaited-coroutine-does-not-mutate-holder",
        ),
        pytest.param(
            'def prepare():\n    holder.text = "echo ok"\n    yield None\n',
            "pending = prepare()\nsubprocess.run(holder.text, shell=True)\n",
            True,
            id="uniterated-generator-does-not-mutate-holder",
        ),
        pytest.param(
            'async def prepare():\n    holder.text = "echo ok"\n',
            "import asyncio\n"
            "async def main():\n"
            "    pending = prepare()\n"
            "    await pending\n"
            "    subprocess.run(holder.text, shell=True)\n"
            "asyncio.run(main())\n",
            False,
            id="awaited-coroutine-applies-holder-mutation",
        ),
    ],
)
def test_deferred_callable_effects_require_execution(tmp_path, prepare, sink, blocked):
    _assert_gate(
        tmp_path,
        dedent(
            """\
            class Holder:
                text = "go build ./..."
            holder = Holder()
            """
        )
        + prepare
        + sink,
        blocked,
    )


@pytest.mark.parametrize(
    ("default", "mapping", "extra", "blocked"),
    [
        pytest.param(
            "echo ok",
            '{"text": "go build ./..."}',
            "",
            True,
            id="unpacked-keyword-overrides-harmless-default",
        ),
        pytest.param(
            "go build ./...",
            '{"text": "echo ok"}',
            "",
            False,
            id="unpacked-keyword-overrides-unsafe-default",
        ),
        pytest.param(
            "echo ok",
            '{"note": "go build ./..."}',
            ", **kwargs",
            False,
            id="unrelated-unpacked-keyword-is-data",
        ),
    ],
)
def test_explicit_unpacked_keywords_bind_by_name(tmp_path, default, mapping, extra, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def command(*, text={default!r}{extra}):
            return text
        subprocess.run(command(**{mapping}), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("returned", "blocked"),
    [
        pytest.param("text", True, id="recursive-base-case-returns-command-argument"),
        pytest.param('"echo ok"', False, id="recursive-base-case-discards-command-argument"),
    ],
)
def test_recursive_call_context_reaches_distinct_base_case(tmp_path, returned, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def command(text, stop):
            if stop:
                return {returned}
            return command(text, True)
        subprocess.run(command("go build ./...", False), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("initial", "overwritten", "blocked"),
    [
        pytest.param("go build ./...", "echo ok", False, id="closure-sees-harmless-overwrite"),
        pytest.param("echo ok", "go build ./...", True, id="closure-sees-unsafe-overwrite"),
    ],
)
def test_returned_closure_reads_final_enclosing_binding(tmp_path, initial, overwritten, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def make():
            text = {initial!r}
            def command():
                return text
            text = {overwritten!r}
            return command
        subprocess.run(make()(), shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("printed", "executed", "blocked"),
    [
        pytest.param("go build ./...", "echo ok", False, id="printed-command-does-not-taint-call"),
        pytest.param("echo ok", "go build ./...", True, id="printed-data-does-not-mark-call-inert"),
    ],
)
def test_invocation_sources_remain_distinct_through_slice(tmp_path, printed, executed, blocked):
    _assert_gate(
        tmp_path,
        f"""\
        def identity(text):
            return text
        print(identity({printed!r}))
        subprocess.run(identity({executed!r})[:], shell=True)
        """,
        blocked,
    )


@pytest.mark.parametrize(
    ("initial", "overwritten", "blocked"),
    [
        pytest.param("echo ok", "go build ./...", True, id="inherited-data-becomes-unsafe"),
        pytest.param("go build ./...", "echo ok", False, id="inherited-data-becomes-harmless"),
    ],
)
def test_inherited_class_method_observes_current_base_attribute(
    tmp_path, initial, overwritten, blocked
):
    _assert_gate(
        tmp_path,
        f"""\
        class Base:
            text = {initial!r}
            @classmethod
            def command(cls):
                return cls.text
        class Child(Base):
            pass
        Base.text = {overwritten!r}
        subprocess.run(Child.command(), shell=True)
        """,
        blocked,
    )


def test_uncertain_local_callable_joins_alternative_attribute_effects(tmp_path):
    _assert_gate(
        tmp_path,
        """\
        import sys
        class Holder:
            text = "echo initial"
        holder = Holder()
        def unsafe():
            holder.text = "go build ./..."
        def harmless():
            holder.text = "echo ok"
        setter = unsafe if len(sys.argv) > 1 else harmless
        setter()
        subprocess.run(holder.text, shell=True)
        """,
        True,
    )


@pytest.mark.parametrize(
    "body",
    [
        "class Holder:\n    stop = False\nholder = Holder()\n"
        'def command():\n    if holder.stop:\n        return "go build ./..."\n'
        "    holder.stop = True\n    return command()\n",
        "stop = False\ndef command():\n    global stop\n"
        '    if stop:\n        return "go build ./..."\n'
        "    stop = True\n    return command()\n",
    ],
    ids=["recursive-attribute-state", "recursive-global-state"],
)
def test_recursive_calls_reconsider_changed_state(tmp_path, body):
    _assert_gate(tmp_path, body + "subprocess.run(command(), shell=True)\n", True)


@pytest.mark.parametrize(
    ("sink", "blocked"),
    [
        ('report().format("go build ./...")\n', False),
        ("subprocess.run(report())\n", True),
    ],
    ids=["large-data-method-is-not-execution", "executed-value-top-fails-closed"],
)
def test_capped_data_and_execution_have_distinct_capabilities(tmp_path, sink, blocked):
    body = f"def report():\n    return {'x' * 5000!r}\n"
    _assert_gate(tmp_path, body + sink, blocked)


def test_recursive_read_only_walk_does_not_taint_scanner_argv(tmp_path):
    _assert_gate(
        tmp_path,
        """\
        def command(root):
            count = 0
            def walk(path):
                nonlocal count
                for entry in path.iterdir():
                    if entry.is_dir():
                        walk(entry)
                    else:
                        count += 1
            walk(root)
            return ["checkov", "--directory", str(root)]
        subprocess.run(command(root))
        """,
        False,
    )


def test_capped_module_aliases_retain_known_execution_capability(tmp_path):
    imports = ["import subprocess as raw"]
    expression = "raw"
    for index in range(70):
        imports.append(f"import module_{index} as namespace_{index}")
        expression = f"namespace_{index} if flag_{index} else ({expression})"
    _assert_gate(
        tmp_path,
        "\n".join(imports)
        + f"\nnamespace = {expression}\n"
        + 'namespace.run(["go", "build", "./..."])\n',
        True,
    )
