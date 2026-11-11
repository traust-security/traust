"""Single entry point: ``traust <group> <op>`` (or ``python3 -m traust.cli``)."""

from __future__ import annotations

import argparse
import sys
from types import SimpleNamespace

from traust.cli.groups import GROUPS
from traust.context import add_config_home_arg


def _split(argv: list[str] | None) -> tuple[str | None, str | None, list[str]]:
    rest = list(argv if argv is not None else sys.argv[1:])
    if not rest:
        return None, None, rest
    if rest[0] in ("-h", "--help"):
        return None, None, rest
    if len(rest) < 2:
        return rest[0], None, rest[1:]
    return rest[0], rest[1], rest[2:]


def _print_top_help() -> None:
    lines = [
        "usage: traust <group> <op> [args...]",
        "",
        "Command groups:",
    ]
    for group in sorted(GROUPS):
        ops = GROUPS[group]
        for op in sorted(ops):
            spec = ops[op]
            help_text = getattr(spec, "help", "") or ""
            lines.append(f"  {group} {op:<16} {help_text}".rstrip())
    lines.append("")
    lines.append("Run traust <group> <op> --help for per-command flags.")
    print("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    group, op, rest = _split(argv)

    if group is None and (not rest or rest[0] in ("-h", "--help")):
        _print_top_help()
        return 0

    if group is None or op is None:
        print("usage: traust <group> <op> [args...]", file=sys.stderr)
        print("       traust --help", file=sys.stderr)
        return 2

    group_ops = GROUPS.get(group)
    if not group_ops or op not in group_ops:
        print(f"unknown command: {group} {op}", file=sys.stderr)
        _print_top_help()
        return 2

    spec = group_ops[op]

    if getattr(spec, "passthrough_argv", False):
        pre = argparse.ArgumentParser(
            prog=f"traust {group} {op}",
            add_help=False,
        )
        add_config_home_arg(pre)
        pre_args, tool_argv = pre.parse_known_args(rest)
        args = SimpleNamespace(config_home=pre_args.config_home, argv=tool_argv)
        # The module owns its own argparse; forwarding argv needs no deployment config.
        return spec.call(args)

    ap = argparse.ArgumentParser(
        prog=f"traust {group} {op}",
        description=getattr(spec, "help", "") or None,
    )
    add_config_home_arg(ap)
    spec.add_args(ap)
    return spec.call(ap.parse_args(rest))


if __name__ == "__main__":
    raise SystemExit(main())
