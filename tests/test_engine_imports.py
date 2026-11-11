"""traust depends on traust-core only: no `traust_engine`, `traust_contracts` or `traust_ledger`
import (static, or through `importlib.import_module`) under src/, harnessing/ or scripts/.

What still imports the engine is counted per file against BASELINE, which only shrinks: a new
file, a higher count or a stale entry fails.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("traust_engine", "traust_contracts", "traust_ledger")
BASELINE: dict[str, int] = {}


def _named(name: str) -> bool:
    return any(name == p or name.startswith(f"{p}.") for p in PACKAGES)


def _package_imports(source: str) -> int:
    count = 0
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            count += sum(_named(a.name) for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            count += _named(node.module)
        elif (
            isinstance(node, ast.Call)
            and isinstance(f := node.func, ast.Attribute | ast.Name)
            and (f.attr if isinstance(f, ast.Attribute) else f.id) == "import_module"
            and node.args
            and isinstance(arg := node.args[0], ast.Constant)
            and isinstance(arg.value, str)
        ):
            count += _named(arg.value)
    return count


def _hits() -> Counter[str]:
    return Counter(
        {
            path.relative_to(ROOT).as_posix(): n
            for root in ("src", "harnessing", "scripts")
            for path in (ROOT / root).rglob("*.py")
            if (n := _package_imports(path.read_text(encoding="utf-8")))
        }
    )


def test_package_imports_never_grow_past_the_baseline() -> None:
    grown = {f: n for f, n in _hits().items() if n > BASELINE.get(f, 0)}
    assert not grown, f"use traust-core's doors instead: {grown}"


def test_the_baseline_only_shrinks() -> None:
    hits = _hits()
    stale = {f: (n, hits[f]) for f, n in BASELINE.items() if hits[f] < n}
    assert not stale, f"lower BASELINE to what remains (baseline, now): {stale}"


def test_counted_imports_include_every_package_and_nested_and_dynamic_ones() -> None:
    source = (
        "import traust_engine\n"
        "from traust_engine.adapters import grype\n"
        "def f():\n"
        "    from traust_engine import HarnessEngine\n"
        "from traust_contracts.config import load_section\n"
        "import traust_ledger.v1\n"
        "importlib.import_module('traust_engine.corpus.resolver')\n"
        "import_module('traust_contracts')\n"
        "from traust_enginex import y\n"
        "from . import traust_engine\n"
        "importlib.import_module('traust_core.v1.context')\n"
        "importlib.import_module(name)\n"
    )
    assert _package_imports(source) == 7
