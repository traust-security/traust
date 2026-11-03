"""Execution-ordered, bounded static values for Python S10 command checks."""

from __future__ import annotations

import ast
import itertools
import re
import shlex
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from traust.cli._s10_commands import unrouted_argv

_SUBPROCESS = frozenset(
    {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
)
_OS = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    }
)
_SAFE = frozenset({"safe_exec.run", "traust_engine._util.safe_exec.run"})
_MAX_VARIANTS = 64
_MAX_TEXT = 4096
_MAX_ITEMS = 64
_MAX_DEPTH = 8


@dataclass(frozen=True)
class _Value:
    origins: frozenset[str] = frozenset()
    strings: frozenset[str] = frozenset()
    argvs: frozenset[tuple[str | None, ...]] = frozenset()
    # Unknown is an unknown whole alternative, not an unknown argument in a known argv.
    unknown: bool = False
    capped: bool = False
    elements: tuple[_Value, ...] | None = None
    literals: frozenset[bool | int | None] = frozenset()
    sources: frozenset[int] = frozenset()


def _depth(value: _Value) -> int:
    return 0 if value.elements is None else 1 + max((_depth(v) for v in value.elements), default=0)


def _join(values: Iterable[_Value]) -> _Value:
    values = tuple(values)
    origins = frozenset().union(*(v.origins for v in values))
    strings = frozenset().union(*(v.strings for v in values))
    argvs = frozenset().union(*(v.argvs for v in values))
    literals = frozenset().union(*(v.literals for v in values))
    sequences = [v.elements for v in values if v.elements is not None]
    elements = None
    if sequences and len({len(v) for v in sequences}) == 1:
        elements = tuple(_join(parts) for parts in zip(*sequences, strict=True))
    capped = (
        any(v.capped for v in values)
        or max(len(origins), len(strings), len(argvs), len(literals)) > _MAX_VARIANTS
        or any(len(s) > _MAX_TEXT for s in strings)
        or any(
            len(a) > _MAX_ITEMS or any(s is not None and len(s) > _MAX_TEXT for s in a)
            for a in argvs
        )
        or any(len(s) > _MAX_TEXT for s in origins)
        or (
            elements is not None
            and (len(elements) > _MAX_ITEMS or any(_depth(v) >= _MAX_DEPTH for v in elements))
        )
    )
    # Once widened, data stays at top. Keeping a changing sample would prevent convergence.
    return _Value(
        origins=frozenset() if capped else origins,
        strings=frozenset() if capped else strings,
        argvs=frozenset() if capped else argvs,
        unknown=any(v.unknown for v in values),
        capped=capped,
        elements=None if capped else elements,
        literals=frozenset() if capped else literals,
        sources=frozenset().union(*(v.sources for v in values)),
    )


_UNKNOWN = _Value(unknown=True)


def _origin(name: str) -> _Value:
    return _Value(origins=frozenset({name}))


def _unbound(name: str) -> _Value:
    implicit = {"subprocess", "os", "shlex", "safe_exec", "print", "argparse"}
    return _Value(origins=frozenset({name}), unknown=name not in implicit)


@dataclass
class _State:
    bindings: dict[str, _Value] = field(default_factory=dict)
    writes: dict[tuple[int, str], _Value] = field(default_factory=dict)
    returned: _Value | None = None

    def copy(self) -> _State:
        return _State(dict(self.bindings), dict(self.writes), self.returned)


def _merge(states: Iterable[_State | None]) -> _State | None:
    states = tuple(state for state in states if state is not None)
    if not states:
        return None
    names = set().union(*(state.bindings for state in states))
    writes = set().union(*(state.writes for state in states))
    returned = [state.returned for state in states if state.returned is not None]
    return _State(
        {name: _join(state.bindings.get(name, _UNKNOWN) for state in states) for name in names},
        {key: _join(state.writes.get(key, _UNKNOWN) for state in states) for key in writes},
        _join(returned) if returned else None,
    )


@dataclass
class _Flow:
    normal: _State | None = None
    breaks: _State | None = None
    continues: _State | None = None
    returns: _State | None = None
    raises: _State | None = None


def _flows(flows: Iterable[_Flow]) -> _Flow:
    flows = tuple(flows)
    return _Flow(
        **{
            kind: _merge(getattr(flow, kind) for flow in flows)
            for kind in _Flow.__dataclass_fields__
        }
    )


@dataclass
class _Scope:
    kind: str
    parent: _Scope | None
    closure: dict[str, _Value]
    locals: set[str]
    globals: set[str]
    nonlocals: set[str]
    history: dict[str, _Value] = field(default_factory=dict)
    candidates: set[int] = field(default_factory=set)
    dynamic_execution: bool = False
    execution_sources: set[int] = field(default_factory=set)
    walrus_owner: _Scope | None = None


@dataclass
class _Deferred:
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.GeneratorExp
    parent: _Scope
    defaults: dict[str, _Value] = field(default_factory=dict)
    scope: _Scope | None = None
    signature: object = None
    iterable: _Value = _UNKNOWN


def _declarations(body: list[ast.stmt]) -> tuple[set[str], set[str], set[str]]:
    local, global_names, nonlocal_names = set(), set(), set()
    pending: list[ast.AST] = list(body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local.add(node.name)
            continue
        if isinstance(
            node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            # Assignment expressions in comprehensions belong to the containing scope.
            if not isinstance(node, ast.Lambda):
                local.update(
                    n.target.id
                    for n in ast.walk(node)
                    if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name)
                )
            continue
        if isinstance(node, ast.Global):
            global_names.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            nonlocal_names.update(node.names)
        elif isinstance(node, ast.Import):
            local.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            local.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            local.add(node.id)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            local.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            local.add(node.rest)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            local.add(node.name)
        pending.extend(ast.iter_child_nodes(node))
    return local - global_names - nonlocal_names, global_names, nonlocal_names


def unrouted_python_build(
    text: str,
    *,
    build_rx: re.Pattern[str],
    shell_check: Callable[[str], bool],
    script_shell_check: Callable[[str], bool] | None = None,
) -> bool:
    """Check executions without evaluating submitted code or discarding unsafe paths."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return (script_shell_check or shell_check)(text)
    analyzer = _Analyzer(build_rx, shell_check)
    module = analyzer.scope("module", None, {}, tree.body)
    analyzer.module = module
    analyzer.block(tree.body, _State(), module)
    analyzer.deferred_bodies()
    analyzer.fallbacks()
    return analyzer.blocked


class _Analyzer:
    def __init__(self, build_rx: re.Pattern[str], shell_check: Callable[[str], bool]) -> None:
        self.build_rx = build_rx
        self.shell_check = shell_check
        self.blocked = False
        self.module: _Scope | None = None
        self.scopes: list[_Scope] = []
        self.deferred: dict[tuple[int, int], _Deferred] = {}
        self.sources: dict[int, _Value] = {}
        self.inert_sources: set[int] = set()
        self.source_dependencies: dict[int, set[int]] = {}
        self.return_sources: dict[str, int] = {}

    def argv(self, argv: tuple[str | None, ...]) -> bool:
        return unrouted_argv(
            argv,
            build_rx=self.build_rx,
            shell_check=self.shell_check,
            python_check=lambda text: unrouted_python_build(
                text, build_rx=self.build_rx, shell_check=self.shell_check
            ),
        )

    def source(self, node: ast.AST, value: _Value) -> _Value:
        key = id(node)
        self.source_dependencies.setdefault(key, set()).update(value.sources - {key})
        plain = replace(value, sources=frozenset())
        self.sources[key] = _join((self.sources[key], plain)) if key in self.sources else plain
        return replace(value, sources=frozenset({key}))

    def local_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> _Value:
        # Definition identity separates same-named helpers in different scopes.
        origin = f"local:{id(node)}"
        self.return_sources[origin] = id(node)
        return _origin(origin)

    def mark_inert(self, sources: Iterable[int]) -> None:
        pending = list(sources)
        while pending:
            source = pending.pop()
            if source in self.inert_sources:
                continue
            self.inert_sources.add(source)
            pending.extend(self.source_dependencies.get(source, ()))

    def scope(
        self, kind: str, parent: _Scope | None, closure: dict[str, _Value], body: list[ast.stmt]
    ) -> _Scope:
        local, global_names, nonlocal_names = _declarations(body)
        scope = _Scope(kind, parent, closure, local, global_names, nonlocal_names)
        self.scopes.append(scope)
        return scope

    def history(self, scope: _Scope | None) -> dict[str, _Value]:
        if scope is None:
            return {}
        if scope.kind == "class":
            return self.history(scope.parent)
        result = dict(scope.closure)
        for name in scope.locals:
            result[name] = scope.history.get(name, _UNKNOWN)
        result.update(scope.history)
        return result

    def owner(self, name: str, scope: _Scope) -> _Scope | None:
        if name in scope.globals:
            return self.module
        if name in scope.nonlocals:
            parent = scope.parent
            while parent is not None:
                if parent.kind != "class" and name in parent.locals:
                    return parent
                parent = parent.parent
        return None

    def lookup(self, name: str, state: _State, scope: _Scope) -> _Value:
        if name in state.bindings:
            return state.bindings[name]
        owner = self.owner(name, scope)
        if owner is not None:
            return state.writes.get((id(owner), name), owner.history.get(name, _unbound(name)))
        if self.module is not None and (id(self.module), name) in state.writes:
            return state.writes[(id(self.module), name)]
        if scope.kind in {"function", "comprehension"} and name in scope.locals:
            return _UNKNOWN
        return scope.closure.get(name, _unbound(name))

    def remember(self, name: str, value: _Value, scope: _Scope) -> None:
        scope.history[name] = (
            _join((scope.history[name], value)) if name in scope.history else value
        )

    def bind(self, name: str, value: _Value, state: _State, scope: _Scope) -> None:
        state.bindings[name] = value
        self.remember(name, value, scope)
        owner = self.owner(name, scope)
        if owner is not None:
            state.writes[(id(owner), name)] = value
            if scope.kind != "class":
                self.remember(name, value, owner)

    def visible(self, state: _State, scope: _Scope) -> dict[str, _Value]:
        result = dict(scope.closure)
        if scope.kind in {"function", "comprehension"}:
            result.update({name: _UNKNOWN for name in scope.locals})
        result.update(state.bindings)
        for (_, name), value in state.writes.items():
            if name not in state.bindings:
                result[name] = value
        return result

    def target(self, node: ast.AST, value: _Value, state: _State, scope: _Scope) -> None:
        if isinstance(node, ast.Name):
            self.bind(node.id, value, state, scope)
        elif isinstance(node, (ast.Tuple, ast.List)):
            star = next(
                (i for i, child in enumerate(node.elts) if isinstance(child, ast.Starred)), None
            )
            for index, child in enumerate(node.elts):
                position = index if star is None or index < star else index - len(node.elts)
                if isinstance(child, ast.Starred):
                    if value.elements is not None:
                        end = len(value.elements) - (len(node.elts) - index - 1)
                        part = self.sequence(value.elements[index:end])
                    else:
                        part = _UNKNOWN
                elif value.elements is not None and -len(value.elements) <= position < len(
                    value.elements
                ):
                    part = value.elements[position]
                else:
                    parts = [
                        _Value(strings=frozenset({args[position]}))
                        for args in value.argvs
                        if -len(args) <= position < len(args) and args[position] is not None
                    ]
                    part = _join(parts) if parts else _UNKNOWN
                self.target(child, part, state, scope)
        elif isinstance(node, ast.Starred):
            self.target(node.value, value, state, scope)
        else:
            self.expr(node, state, scope)

    def block(self, body: list[ast.stmt], state: _State, scope: _Scope) -> _Flow:
        flow = _Flow(normal=state)
        for statement in body:
            if flow.normal is None:
                break
            step = self.statement(statement, flow.normal, scope)
            flow = _flows((replace(flow, normal=None), step))
        return flow

    def statement(self, node: ast.stmt, state: _State, scope: _Scope) -> _Flow:
        if isinstance(node, ast.Expr):
            if not isinstance(node.value, ast.Constant):
                self.expr(node.value, state, scope)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                self.bind(
                    alias.asname or alias.name.split(".")[0],
                    _origin(alias.name if alias.asname else alias.name.split(".")[0]),
                    state,
                    scope,
                )
        elif isinstance(node, ast.ImportFrom):
            module = ("." * node.level) + (node.module or "")
            names = (
                _SUBPROCESS
                if module == "subprocess"
                else _OS
                if module == "os"
                else {"run"}
                if module in {"safe_exec", "traust_engine._util.safe_exec"}
                else set()
            )
            for alias in node.names:
                if alias.name == "*":
                    for name in names:
                        self.bind(name, _origin(f"{module}.{name}"), state, scope)
                else:
                    self.bind(
                        alias.asname or alias.name, _origin(f"{module}.{alias.name}"), state, scope
                    )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = self.expr(node.value, state, scope) if node.value is not None else _UNKNOWN
            scope.candidates.update(value.sources)
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                self.target(target, value, state, scope)
            if isinstance(node, ast.AnnAssign):
                self.expr(node.annotation, state, scope)
        elif isinstance(node, ast.AugAssign):
            left, right = self.expr(node.target, state, scope), self.expr(node.value, state, scope)
            value = (
                self.source(node, self.add(left, right))
                if isinstance(node.op, ast.Add)
                else _UNKNOWN
            )
            scope.candidates.update(value.sources)
            self.target(node.target, value, state, scope)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self.target(target, _UNKNOWN, state, scope)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for value in node.decorator_list:
                self.expr(value, state, scope)
            defaults = self.defaults(node.args, state, scope)
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                self.expr(arg.annotation, state, scope)
            self.expr(node.returns, state, scope)
            self.bind(node.name, self.local_function(node), state, scope)
            self.defer(node, scope.parent if scope.kind == "class" else scope, defaults)
        elif isinstance(node, ast.ClassDef):
            for value in [*node.decorator_list, *node.bases, *(kw.value for kw in node.keywords)]:
                self.expr(value, state, scope)
            closure = dict(scope.closure) if scope.kind == "class" else self.visible(state, scope)
            parent = scope.parent if scope.kind == "class" else scope
            child = self.scope("class", parent, closure, node.body)
            entry = _State(writes=dict(state.writes))
            for name in child.globals | child.nonlocals:
                owner = self.owner(name, child)
                value = (
                    self.lookup(name, state, scope)
                    if owner is scope
                    else state.writes.get(
                        (id(owner), name),
                        closure.get(name, owner.history.get(name, _unbound(name))),
                    )
                    if owner
                    else _UNKNOWN
                )
                entry.bindings[name] = value
                if owner:
                    entry.writes[(id(owner), name)] = value
            result = self.block(node.body, entry, child)
            if result.normal is not None:
                for (owner, name), value in result.normal.writes.items():
                    if owner == id(scope):
                        self.bind(name, value, state, scope)
                    else:
                        state.writes[(owner, name)] = value
            else:
                return _Flow(raises=result.raises, returns=result.returns)
            self.bind(node.name, _origin(f"local:{node.name}"), state, scope)
        elif isinstance(node, ast.If):
            test = self.expr(node.test, state, scope)
            truth = self.truth(test)
            if truth is not None:
                return self.block(node.body if truth else node.orelse, state, scope)
            return _flows(
                (
                    self.block(node.body, state.copy(), scope),
                    self.block(node.orelse, state.copy(), scope),
                )
            )
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            return self.loop(node, state, scope)
        elif isinstance(node, (ast.Try, ast.TryStar)):
            body = self.block(node.body, state.copy(), scope)
            normal = (
                self.block(node.orelse, body.normal, scope) if body.normal is not None else _Flow()
            )
            paths = [replace(body, normal=None), normal]
            if node.handlers:
                entry = _merge((state, body.normal, body.raises, _State(dict(scope.history))))
                for handler in node.handlers:
                    branch = entry.copy()
                    self.expr(handler.type, branch, scope)
                    if handler.name:
                        self.bind(handler.name, _UNKNOWN, branch, scope)
                    paths.append(self.block(handler.body, branch, scope))
            flow = _flows(paths)
            if node.finalbody:
                finalized = []
                for kind in _Flow.__dataclass_fields__:
                    branch = getattr(flow, kind)
                    if branch is None:
                        continue
                    final = self.block(node.finalbody, branch.copy(), scope)
                    preserved = _Flow(**{kind: final.normal})
                    finalized.extend((preserved, replace(final, normal=None)))
                flow = _flows(finalized)
            return flow
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self.expr(item.context_expr, state, scope)
                if item.optional_vars is not None:
                    self.target(item.optional_vars, value, state, scope)
            return self.block(node.body, state, scope)
        elif isinstance(node, ast.Match):
            subject = self.expr(node.subject, state, scope)
            paths = []
            exhaustive = False
            for case in node.cases:
                branch = state.copy()
                irrefutable = self.pattern(case.pattern, subject, branch, scope)
                guard = self.expr(case.guard, branch, scope) if case.guard else None
                if guard is None or self.truth(guard) is not False:
                    paths.append(self.block(case.body, branch, scope))
                if irrefutable and (guard is None or self.truth(guard) is True):
                    exhaustive = True
                    break
            if not exhaustive:
                paths.append(_Flow(normal=state))
            return _flows(paths)
        elif isinstance(node, ast.Return):
            state.returned = (
                self.expr(node.value, state, scope)
                if node.value is not None
                else _Value(literals=frozenset({None}))
            )
            return _Flow(returns=state)
        elif isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, state, scope)
            kind = (
                "raises"
                if isinstance(node, ast.Raise)
                else "breaks"
                if isinstance(node, ast.Break)
                else "continues"
            )
            return _Flow(**{kind: state})
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, state, scope)
        return _Flow(normal=state)

    def loop(self, node: ast.For | ast.AsyncFor | ast.While, state: _State, scope: _Scope) -> _Flow:
        iterable = (
            self.expr(node.iter, state, scope)
            if isinstance(node, (ast.For, ast.AsyncFor))
            else None
        )
        if (
            iterable is not None
            and iterable.elements == ()
            and not iterable.unknown
            and not iterable.capped
        ):
            return self.block(node.orelse, state, scope)
        head = state.copy()
        terminals = _Flow()
        exhausted = None
        while True:
            entry = head.copy()
            if iterable is None:
                test = self.expr(node.test, entry, scope)
                truth = self.truth(test)
                if truth is not True:
                    exhausted = _merge((exhausted, entry))
                if truth is False:
                    break
            else:
                exhausted = _merge((exhausted, entry))
                item = _join(iterable.elements) if iterable.elements else _UNKNOWN
                self.target(node.target, item, entry, scope)
            body = self.block(node.body, entry, scope)
            terminals = _flows((terminals, replace(body, normal=None, continues=None)))
            following = _merge((state, body.normal, body.continues))
            if following == head:
                break
            head = following
        otherwise = self.block(node.orelse, exhausted, scope) if exhausted is not None else _Flow()
        return _flows(
            (
                otherwise,
                _Flow(normal=terminals.breaks, returns=terminals.returns, raises=terminals.raises),
            )
        )

    def pattern(self, node: ast.pattern, value: _Value, state: _State, scope: _Scope) -> bool:
        if isinstance(node, ast.MatchAs):
            irrefutable = node.pattern is None or self.pattern(node.pattern, value, state, scope)
            if node.name:
                self.bind(node.name, value, state, scope)
            return irrefutable
        if isinstance(node, ast.MatchStar):
            if node.name:
                self.bind(node.name, value, state, scope)
            return True
        if isinstance(node, ast.MatchOr):
            branches = []
            irrefutable = False
            for pattern in node.patterns:
                branch = state.copy()
                irrefutable |= self.pattern(pattern, value, branch, scope)
                branches.append(branch)
            merged = _merge(branches)
            state.bindings, state.writes = merged.bindings, merged.writes
            return irrefutable
        if isinstance(node, ast.MatchSequence):
            for index, pattern in enumerate(node.patterns):
                part = (
                    value.elements[index]
                    if value.elements is not None and index < len(value.elements)
                    else _UNKNOWN
                )
                self.pattern(pattern, part, state, scope)
        elif isinstance(node, ast.MatchMapping):
            for pattern in node.patterns:
                self.pattern(pattern, _UNKNOWN, state, scope)
            if node.rest:
                self.bind(node.rest, _UNKNOWN, state, scope)
        elif isinstance(node, ast.MatchClass):
            self.expr(node.cls, state, scope)
            for pattern in [*node.patterns, *node.kwd_patterns]:
                self.pattern(pattern, _UNKNOWN, state, scope)
        return False

    def defaults(self, args: ast.arguments, state: _State, scope: _Scope) -> dict[str, _Value]:
        positional = [*args.posonlyargs, *args.args]
        result = {
            arg.arg: self.expr(value, state, scope)
            for arg, value in zip(
                positional[len(positional) - len(args.defaults) :], args.defaults, strict=True
            )
        }
        result.update(
            {
                arg.arg: self.expr(value, state, scope)
                for arg, value in zip(args.kwonlyargs, args.kw_defaults, strict=True)
                if value is not None
            }
        )
        return result

    def defer(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.GeneratorExp,
        parent: _Scope | None,
        defaults: dict[str, _Value] | None = None,
        *,
        iterable: _Value = _UNKNOWN,
    ) -> None:
        if parent is None:
            return
        key = (id(node), id(parent))
        if key not in self.deferred:
            self.deferred[key] = _Deferred(node, parent, defaults or {}, iterable=iterable)
        else:
            deferred = self.deferred[key]
            deferred.iterable = _join((deferred.iterable, iterable))
            for name, value in (defaults or {}).items():
                deferred.defaults[name] = _join((deferred.defaults.get(name, value), value))

    def deferred_bodies(self) -> None:
        while True:
            changed = False
            for deferred in tuple(self.deferred.values()):
                closure = self.history(deferred.parent)
                signature = (closure, dict(deferred.defaults), deferred.iterable)
                if deferred.signature == signature:
                    continue
                deferred.signature = signature
                changed = True
                node = deferred.node
                if isinstance(node, ast.GeneratorExp):
                    self.comprehension(
                        node,
                        _State(),
                        deferred.parent,
                        iterable=deferred.iterable,
                        closure=closure,
                        deferred=deferred,
                    )
                    continue
                body = (
                    node.body if not isinstance(node, ast.Lambda) else [ast.Expr(value=node.body)]
                )
                if deferred.scope is None:
                    deferred.scope = self.scope("function", deferred.parent, closure, body)
                scope = deferred.scope
                scope.closure = closure
                arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                arguments += [arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None]
                scope.locals.update(arg.arg for arg in arguments)
                state = _State(
                    {
                        arg.arg: _join((deferred.defaults[arg.arg], _UNKNOWN))
                        if arg.arg in deferred.defaults
                        else _UNKNOWN
                        for arg in arguments
                    }
                )
                for name, value in state.bindings.items():
                    self.remember(name, value, scope)
                if isinstance(node, ast.Lambda):
                    self.source(node, self.expr(node.body, state, scope))
                else:
                    flow = self.block(body, state, scope)
                    if flow.returns is not None and flow.returns.returned is not None:
                        self.source(node, flow.returns.returned)
            if not changed:
                break

    def fallbacks(self) -> None:
        for scope in self.scopes:
            if not scope.dynamic_execution:
                continue
            pending = [(source, True) for source in scope.execution_sources]
            parent: _Scope | None = scope
            while parent is not None:
                pending.extend((source, False) for source in parent.candidates - self.inert_sources)
                parent = parent.parent
            visited = set()
            while pending:
                source, executed = pending.pop()
                if (source, executed) in visited:
                    continue
                visited.add((source, executed))
                value = self.sources.get(source, _UNKNOWN)
                # Only execution-linked top values fail closed; unrelated report
                # data must still contain concrete command evidence to be a candidate.
                if (
                    (value.capped and executed)
                    or any(self.shell_check(text) for text in value.strings)
                    or any(self.argv(argv) for argv in value.argvs)
                ):
                    self.blocked = True
                if value.unknown:
                    pending.extend(
                        (dependency, executed)
                        for dependency in self.source_dependencies.get(source, ())
                    )

    def add(self, left: _Value, right: _Value) -> _Value:
        if left.capped or right.capped:
            return _join((_Value(capped=True), left, right))
        strings, argvs = set(), set()
        capped = False
        for a, b in itertools.product(left.strings, right.strings):
            strings.add(a + b)
            if len(strings) > _MAX_VARIANTS:
                capped = True
                break
        left_argvs = left.argvs or (frozenset({(None,)}) if left.unknown else frozenset())
        right_argvs = right.argvs or (frozenset({(None,)}) if right.unknown else frozenset())
        for a, b in itertools.product(left_argvs, right_argvs):
            argvs.add(a + b)
            if len(argvs) > _MAX_VARIANTS:
                capped = True
                break
        elements = (
            left.elements + right.elements
            if left.elements is not None and right.elements is not None
            else None
        )
        return _join(
            (
                _Value(
                    strings=frozenset(strings),
                    argvs=frozenset(argvs),
                    unknown=(left.unknown or right.unknown) and not (left.argvs or right.argvs),
                    capped=capped,
                    elements=elements,
                    sources=left.sources | right.sources,
                ),
            )
        )

    def sequence(self, elements: Iterable[_Value]) -> _Value:
        elements = tuple(elements)
        argvs: set[tuple[str | None, ...]] = {()}
        capped = False
        for value in elements:
            tokens = value.strings | (
                frozenset({None}) if value.unknown or not value.strings else frozenset()
            )
            variants = set()
            for argv, token in itertools.product(argvs, tokens):
                variants.add((*argv, token))
                if len(variants) > _MAX_VARIANTS:
                    capped = True
                    break
            argvs = variants
            capped |= value.capped
        return _join(
            (
                _Value(
                    argvs=frozenset(argvs),
                    elements=elements,
                    capped=capped,
                    sources=frozenset().union(*(value.sources for value in elements)),
                ),
            )
        )

    def truth(self, value: _Value) -> bool | None:
        if value.unknown or value.capped:
            return None
        possibilities = {bool(v) for v in value.strings | value.literals | value.argvs}
        if value.origins:
            possibilities.add(True)
        return next(iter(possibilities)) if len(possibilities) == 1 else None

    def comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        state: _State,
        scope: _Scope,
        *,
        iterable: _Value = _UNKNOWN,
        closure: dict[str, _Value] | None = None,
        deferred: _Deferred | None = None,
    ) -> _Value:
        if iterable.elements == () and not iterable.unknown and not iterable.capped:
            return _UNKNOWN
        parent = scope.parent if scope.kind == "class" else scope
        captured = (
            closure
            if closure is not None
            else dict(scope.closure)
            if scope.kind == "class"
            else self.visible(state, scope)
        )
        if deferred is not None and deferred.scope is not None:
            child = deferred.scope
            child.closure = captured
        else:
            child = self.scope("comprehension", parent, captured, [])
            if deferred is not None:
                deferred.scope = child
        child.walrus_owner = scope.walrus_owner or scope
        child.locals.update(
            target.id
            for generator in node.generators
            for target in ast.walk(generator.target)
            if isinstance(target, ast.Name)
        )
        child_state = _State()
        for index, generator in enumerate(node.generators):
            current = self.expr(generator.iter, child_state, child) if index else iterable
            item = _join(current.elements) if current.elements else _UNKNOWN
            self.target(generator.target, item, child_state, child)
            for condition in generator.ifs:
                self.expr(condition, child_state, child)
        if isinstance(node, ast.DictComp):
            self.expr(node.key, child_state, child)
            self.expr(node.value, child_state, child)
        else:
            self.expr(node.elt, child_state, child)
        for (owner, name), value in child_state.writes.items():
            if owner == id(scope):
                self.bind(name, _join((self.lookup(name, state, scope), value)), state, scope)
            else:
                previous = state.writes.get((owner, name), _UNKNOWN)
                state.writes[(owner, name)] = _join((previous, value))
        return _UNKNOWN

    def expr(self, node: ast.AST | None, state: _State, scope: _Scope) -> _Value:
        if node is None:
            return _UNKNOWN
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return self.source(node, _Value(strings=frozenset({node.value})))
            if node.value is None or isinstance(node.value, (bool, int)):
                return _Value(literals=frozenset({node.value}))
            return _UNKNOWN
        if isinstance(node, ast.Name):
            return self.lookup(node.id, state, scope)
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, state, scope)
            return _join(
                (
                    _Value(
                        origins=frozenset(f"{name}.{node.attr}" for name in base.origins),
                        unknown=base.unknown,
                        capped=base.capped,
                    ),
                )
            )
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value, state, scope)
            scope.candidates.update(value.sources)
            if (
                scope.kind == "comprehension"
                and isinstance(node.target, ast.Name)
                and scope.walrus_owner is not None
            ):
                owner = scope.walrus_owner
                state.writes[(id(owner), node.target.id)] = value
                self.remember(node.target.id, value, owner)
                # Input closures are also deferred-work signatures; never mutate them.
                state.bindings[node.target.id] = value
            else:
                self.target(node.target, value, state, scope)
            return value
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = self.sequence(())
            for item in node.elts:
                part = (
                    self.expr(item.value, state, scope)
                    if isinstance(item, ast.Starred)
                    else self.sequence((self.expr(item, state, scope),))
                )
                result = self.add(result, part)
            return self.source(node, result)
        if isinstance(node, ast.BinOp):
            left, right = self.expr(node.left, state, scope), self.expr(node.right, state, scope)
            return (
                self.source(node, self.add(left, right))
                if isinstance(node.op, ast.Add)
                else _Value(unknown=True, sources=left.sources | right.sources)
            )
        if isinstance(node, ast.JoinedStr):
            result = _Value(strings=frozenset({""}))
            for item in node.values:
                value = self.expr(
                    item.value if isinstance(item, ast.FormattedValue) else item, state, scope
                )
                strings = value.strings or frozenset({"__dynamic__"})
                result = self.add(result, _Value(strings=strings, capped=value.capped))
            return self.source(node, result)
        if isinstance(node, ast.BoolOp):
            branches, values = [], []
            for index, operand in enumerate(node.values):
                value = self.expr(operand, state, scope)
                truth = self.truth(value)
                stop = truth is True if isinstance(node.op, ast.Or) else truth is False
                if stop or index == len(node.values) - 1:
                    branches.append(state.copy())
                    values.append(value)
                    break
                if truth is None:
                    branches.append(state.copy())
                    values.append(value)
            merged = _merge(branches)
            state.bindings, state.writes = merged.bindings, merged.writes
            return _join(values)
        if isinstance(node, ast.IfExp):
            test = self.expr(node.test, state, scope)
            truth = self.truth(test)
            if truth is not None:
                return self.expr(node.body if truth else node.orelse, state, scope)
            left, right = state.copy(), state.copy()
            values = (self.expr(node.body, left, scope), self.expr(node.orelse, right, scope))
            merged = _merge((left, right))
            state.bindings, state.writes = merged.bindings, merged.writes
            return _join(values)
        if isinstance(node, ast.Lambda):
            self.defer(
                node,
                scope.parent if scope.kind == "class" else scope,
                self.defaults(node.args, state, scope),
            )
            return self.local_function(node)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            iterable = self.expr(node.generators[0].iter, state, scope)
            value = self.comprehension(node, state, scope, iterable=iterable)
            if isinstance(node, ast.GeneratorExp):
                self.defer(
                    node, scope.parent if scope.kind == "class" else scope, iterable=iterable
                )
            return value
        if isinstance(node, ast.Call):
            return self.call(node, state, scope)
        if isinstance(node, ast.Compare):
            self.expr(node.left, state, scope)
            branches = []
            for index, comparator in enumerate(node.comparators):
                if index:
                    branches.append(state.copy())
                self.expr(comparator, state, scope)
            if branches:
                merged = _merge((*branches, state))
                state.bindings, state.writes = merged.bindings, merged.writes
            return _UNKNOWN
        sources = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                sources.update(self.expr(child, state, scope).sources)
        return _Value(unknown=True, sources=frozenset(sources))

    def literal(self, value: _Value, default: object = None) -> object:
        if value.unknown or value.capped:
            return default
        options = set(value.strings) | set(value.literals)
        return next(iter(options)) if len(options) == 1 else default

    def split(
        self,
        node: ast.Call,
        function: _Value,
        args: list[_Value],
        kwargs: dict[str | None, _Value],
        state: _State,
        scope: _Scope,
    ) -> _Value | None:
        shell = "shlex.split" in function.origins
        string = isinstance(node.func, ast.Attribute) and node.func.attr == "split" and not shell
        if not shell and not string:
            return None
        source = (
            args[0]
            if shell and args
            else self.expr(node.func.value, state, scope)
            if string
            else _UNKNOWN
        )
        options = args[1:] if shell else args
        names = ("comments", "posix") if shell else ("sep", "maxsplit")
        defaults = (False, True) if shell else (None, -1)
        missing = object()
        resolved = []
        valid = len(options) <= 2 and all(name in names for name in kwargs)
        for index, name in enumerate(names):
            option = options[index] if index < len(options) else kwargs.get(name)
            resolved.append(defaults[index] if option is None else self.literal(option, missing))
            valid &= resolved[-1] is not missing and not (index < len(options) and name in kwargs)
        argvs = set()
        unknown = source.unknown or not valid
        if valid:
            for text in source.strings:
                try:
                    result = (
                        shlex.split(text, comments=resolved[0], posix=resolved[1])
                        if shell
                        else text.split(resolved[0], resolved[1])
                    )
                    argvs.add(tuple(result))
                except (TypeError, ValueError):
                    unknown = True
        value = _join(
            (
                _Value(
                    argvs=frozenset(argvs),
                    unknown=unknown or not argvs,
                    capped=source.capped,
                    sources=source.sources,
                ),
            )
        )
        return self.source(node, value) if argvs or value.capped else value

    def execute(self, command: _Value, scope: _Scope, *, shell: bool | None = False) -> None:
        if command.capped:
            self.blocked = True
        if any(self.shell_check(text) for text in command.strings):
            self.blocked = True
        if shell is not True and any(self.argv(argv) for argv in command.argvs):
            self.blocked = True
        if shell is not False and any(
            argv and argv[0] is not None and self.shell_check(argv[0]) for argv in command.argvs
        ):
            self.blocked = True
        unknown_shell = shell is not False and any(
            argv and argv[0] is None for argv in command.argvs
        )
        if (
            command.unknown
            or unknown_shell
            or (not command.strings and not command.argvs and not command.capped)
        ):
            scope.dynamic_execution = True
            scope.execution_sources.update(command.sources)
            if unknown_shell and command.elements:
                scope.execution_sources.update(command.elements[0].sources)
        else:
            # A proven argv execution does not make its data arguments shell candidates.
            self.mark_inert(command.sources)

    def call(self, node: ast.Call, state: _State, scope: _Scope) -> _Value:
        function = self.expr(node.func, state, scope)
        args = [self.expr(arg, state, scope) for arg in node.args]
        kwargs = {kw.arg: self.expr(kw.value, state, scope) for kw in node.keywords}
        split = self.split(node, function, args, kwargs, state, scope)
        if split is not None:
            return split
        if function.capped:
            self.execute(
                args[0] if args else kwargs.get("args", kwargs.get("cmd", _UNKNOWN)), scope
            )
            return _UNKNOWN
        safe = bool(function.origins) and function.origins <= _SAFE and not function.unknown
        printed = function.origins == frozenset({"print"}) and not function.unknown
        argparse = any(name.startswith("argparse.") for name in function.origins)
        add_argument = isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"
        if safe or printed:
            for value in [*args, *kwargs.values()]:
                self.mark_inert(value.sources)
        elif argparse or add_argument:
            for name in ("description", "help"):
                if name in kwargs:
                    self.mark_inert(kwargs[name].sources)
        executed = False
        for name in function.origins:
            module, _, operation = name.rpartition(".")
            command = None
            shell: bool | None = False
            if module == "subprocess" and operation in _SUBPROCESS:
                command = args[0] if args else kwargs.get("args", kwargs.get("cmd"))
                if "shell" in kwargs:
                    missing = object()
                    mode = self.literal(kwargs["shell"], missing)
                    shell = None if mode is missing else bool(mode)
            elif module == "os" and operation in {"system", "popen"}:
                command = args[0] if args else kwargs.get("command", kwargs.get("cmd"))
                shell = True
            elif module == "os" and operation in _OS:
                offset = 2 if operation.startswith("spawn") else 1
                path = (
                    args[offset - 1]
                    if len(args) >= offset
                    else kwargs.get("path", kwargs.get("file", _UNKNOWN))
                )
                vector = "v" in operation.removeprefix("spawn").removeprefix("exec")
                if vector:
                    supplied = args[offset] if len(args) > offset else kwargs.get("args", _UNKNOWN)
                    tails = {argv[1:] for argv in supplied.argvs}
                    command = _Value(
                        argvs=frozenset(
                            (executable, *tail)
                            for executable, tail in itertools.product(path.strings or {None}, tails)
                        ),
                        unknown=supplied.unknown,
                        capped=supplied.capped or path.capped,
                        sources=supplied.sources | path.sources,
                    )
                else:
                    supplied = args[offset:]
                    if operation.endswith("e") and supplied:
                        supplied = supplied[:-1]
                    command = self.sequence((path, *supplied[1:]))
                    command = replace(
                        command,
                        sources=frozenset().union(*(arg.sources for arg in [path, *supplied])),
                    )
            if command is not None:
                executed = True
                self.execute(command, scope, shell=shell)
        if executed or safe or printed:
            return _UNKNOWN
        sources = set().union(*(value.sources for value in [*args, *kwargs.values()]))
        sources.update(
            self.return_sources[name] for name in function.origins if name in self.return_sources
        )
        return _Value(unknown=True, sources=frozenset(sources))
