"""Classify CLI modules from their static Python importers and literal skill references."""

from __future__ import annotations

import ast
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from traust_core.v1.errors import ValidationError

from traust.cli._doors import parser, run
from traust.paths import HARNESS_ROOT, skill_md_paths

CLASSES = ("shared-library", "multi-skill-cli", "single-skill-cli", "orphan", "other")
_SKIP = frozenset({".git", ".venv", "__pycache__", "clones", "node_modules", "vendor"})


@dataclass(frozen=True)
class Placement:
    module: str
    classification: str
    non_test_importers: int
    total_importers: int
    skill_refs: int
    path: Path


def _imports(path: Path, modules: set[str]) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeError) as error:
        raise ValidationError(f"cannot inspect Python imports in {path}: {error}") from error
    names = {name: name for name in modules}
    names.update({f"traust.cli.{name}": name for name in modules})
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(names[alias.name] for alias in node.names if alias.name in names)
        elif isinstance(node, ast.ImportFrom):
            if node.module in names:
                found.add(names[node.module])
            elif node.module == "traust.cli" or (node.module is None and node.level):
                found.update(alias.name for alias in node.names if alias.name in modules)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "passthrough_op"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in modules
        ):
            found.add(node.args[0].value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_ENTRIES"
            and isinstance(node.value, ast.Tuple)
        ):
            found.update(
                entry.elts[1].value
                for entry in node.value.elts
                if isinstance(entry, ast.Tuple)
                and len(entry.elts) == 3
                and isinstance(entry.elts[1], ast.Constant)
                and entry.elts[1].value in modules
            )
    return found


def classify(root: Path = HARNESS_ROOT) -> tuple[list[Placement], dict[str, int]]:
    cli = root / "src" / "traust" / "cli"
    if not cli.is_dir():
        raise ValidationError(f"harness CLI directory is missing: {cli}")
    scripts = {p.stem: p for p in cli.glob("*.py") if p.is_file() and p.stem != "__init__"}
    modules = set(scripts)
    importers: dict[str, set[Path]] = defaultdict(set)
    non_test: dict[str, set[Path]] = defaultdict(set)
    for scan in (root / "src" / "traust", root / "harnessing", root / "tests"):
        for path in sorted(scan.rglob("*.py")):
            if path.is_symlink() or any(part in _SKIP for part in path.relative_to(root).parts):
                continue
            for module in _imports(path, modules):
                if scripts[module] == path:
                    continue
                importers[module].add(path)
                if "tests" not in path.relative_to(root).parts and not path.name.startswith(
                    "test_"
                ):
                    non_test[module].add(path)
    refs: dict[str, set[Path]] = defaultdict(set)
    for skill in skill_md_paths(root):
        text = skill.read_text(encoding="utf-8")
        for module in modules:
            if f"{module}.py" in text or f"traust.cli.{module}" in text:
                refs[module].add(skill)
    rows = []
    counts = dict.fromkeys(CLASSES, 0)
    for module, path in sorted(scripts.items()):
        imported, referenced = len(non_test[module]), len(refs[module])
        classification = (
            "shared-library"
            if imported >= 3
            else "multi-skill-cli"
            if referenced >= 2
            else "single-skill-cli"
            if referenced == 1 and imported == 0
            else "orphan"
            if referenced == 0 and imported == 0
            else "other"
        )
        counts[classification] += 1
        rows.append(
            Placement(module, classification, imported, len(importers[module]), referenced, path)
        )
    return rows, counts


def main(argv: list[str] | None = None) -> int:
    ap = parser(
        "check", "script-placement", "Classify CLI placement from static callers and skills."
    )
    ap.add_argument("--root", type=Path, default=HARNESS_ROOT, help="harness checkout to inspect")
    ap.add_argument("--only", choices=CLASSES)
    args = ap.parse_args(argv)

    def call() -> None:
        rows, counts = classify(args.root.resolve())
        writer = csv.writer(sys.stdout)
        writer.writerow(("class", "count"))
        writer.writerows(counts.items())
        writer.writerow(())
        writer.writerow(
            ("module", "class", "non_test_importers", "total_importers", "skill_refs", "path")
        )
        writer.writerows(
            (
                row.module,
                row.classification,
                row.non_test_importers,
                row.total_importers,
                row.skill_refs,
                str(row.path),
            )
            for row in rows
            if args.only is None or row.classification == args.only
        )

    return run(call)


if __name__ == "__main__":
    raise SystemExit(main())
