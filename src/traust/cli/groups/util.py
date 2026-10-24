"""``traust util …`` — engine util wrappers (redact, elf, safe-exec)."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

from traust_engine._util import elf as elf_util
from traust_engine._util import redact as redact_util
from traust_engine._util import safe_exec

from traust.cli.groups._registry import OpSpec


def add_redact_args(ap) -> None:
    ap.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to redact in place (default: stdin)",
    )
    ap.add_argument(
        "--scan-only",
        action="store_true",
        help="Detect secrets without modifying files (validate_report --strict gate)",
    )


def call_redact(_engine, args) -> int:
    if not args.paths:
        text = sys.stdin.read()
        if args.scan_only:
            hits = redact_util.scan_text(text)
            print(json.dumps(hits, indent=2))
            return 1 if hits else 0
        cleaned, hits = redact_util.redact_text(text)
        sys.stdout.write(cleaned)
        if hits:
            print(f"redact: {len(hits)} hit(s) on stdin", file=sys.stderr)
        return 0

    total_hits = 0
    for raw in args.paths:
        path = Path(raw)
        if path.is_dir():
            files = sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink())
        else:
            files = [path]
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                print(f"skip {f}: {e}", file=sys.stderr)
                continue
            if args.scan_only:
                hits = redact_util.scan_text(text)
            else:
                text, hits = redact_util.redact_text(text)
                if hits:
                    f.write_text(text, encoding="utf-8")
            total_hits += len(hits)
            for h in hits:
                print(f"{f}: {h['category']} ({h['match_prefix']}…)")
    if args.scan_only and total_hits:
        return 1
    print(f"redact: {total_hits} hit(s) across {len(args.paths)} path(s)")
    return 0


REDACT = OpSpec(add_args=add_redact_args, call=call_redact, help="Redact secrets in text or files")


def add_elf_args(ap) -> None:
    ap.add_argument("binary", type=Path, help="ELF binary to analyze")
    ap.add_argument(
        "--symbol",
        action="append",
        default=[],
        metavar="NAME",
        help="Symbol name to search for in binary strings (repeatable)",
    )
    ap.add_argument(
        "--max-scan-mb",
        type=int,
        default=32,
        help="Max bytes to scan for string patterns (default 32)",
    )


def call_elf(_engine, args) -> int:
    path = args.binary.resolve()
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    analyzer = elf_util.ElfAnalyzer(path)
    meta = analyzer.metadata()
    if meta is None:
        print(f"not an ELF binary: {path}", file=sys.stderr)
        return 1
    out: dict = {
        "path": str(path),
        "metadata": {
            "arch": meta.arch,
            "elf_class": meta.elf_class,
            "endian": meta.endian,
        },
        "linked_libraries": [lib.name for lib in analyzer.linked_libraries()],
    }
    if args.symbol:
        patterns = [
            (name, re.compile(name.encode("ascii", errors="ignore"))) for name in args.symbol
        ]
        matches = analyzer.scan_strings(
            patterns,
            max_scan=args.max_scan_mb * 1_000_000,
        )
        out["string_matches"] = [
            {"pattern_id": m.pattern_id, "matched": m.matched, "offset": m.offset} for m in matches
        ]
    print(json.dumps(out, indent=2))
    return 0


ELF = OpSpec(
    add_args=add_elf_args, call=call_elf, help="ELF metadata, linked libs, optional string scan"
)


def add_safe_exec_args(ap) -> None:
    sub = ap.add_subparsers(dest="safe_exec_mode", required=True)
    for mode in ("check", "run"):
        p = sub.add_parser(mode, help=f"{mode} a command under a safe_exec profile")
        p.add_argument("--profile", required=True)
        p.add_argument(
            "--string",
            default=None,
            help="command as one string (pipeline-capable); otherwise pass argv after --",
        )
        p.add_argument("--timeout", type=int, default=120)
        p.add_argument("--cwd", default=None)
        p.add_argument(
            "--allowed-host",
            action="append",
            default=[],
            metavar="HOST",
            dest="allowed_hosts",
            help="extra curl host for this invocation (repeatable); unions "
            "with the profile's curl_allowed_hosts",
        )
        p.add_argument("cmd", nargs="*", help="argv form (after --)")
    sub.add_parser("list-profiles", help="list configured safe_exec profiles")


def call_safe_exec(engine, args) -> int:
    profile_map = engine.adapters.safe_exec_profile_map()
    if args.safe_exec_mode == "list-profiles":
        for name, profile in sorted(profile_map.items()):
            hosts = (
                f"{len(profile.curl_allowed_hosts)} listed"
                if profile.curl_allowed_hosts
                else "none listed"
            )
            print(
                f"{name:18s} posture={profile.posture} allow={sorted(profile.allow)} "
                f"pipelines={profile.allow_pipelines} "
                f"curl_hosts={hosts} — {profile.description}"
            )
        return 0

    mode = os.environ.get("SAFE_EXEC_MODE", "enforce").lower()
    if args.string is not None and args.cmd:
        print("pass either --string or argv, not both", file=sys.stderr)
        return 2
    cmd = args.string if args.string is not None else args.cmd
    allowed_hosts = tuple(args.allowed_hosts or ())
    if isinstance(cmd, str):
        verdict = safe_exec.vet_command_string(
            cmd,
            safe_exec.get_profile(args.profile, profile_map=profile_map),
            allowed_hosts=allowed_hosts,
        )
    else:
        verdict = safe_exec.validate_argv(
            list(cmd),
            safe_exec.get_profile(args.profile, profile_map=profile_map),
            allowed_hosts=allowed_hosts,
        )

    if args.safe_exec_mode == "check":
        if verdict.ok:
            print("OK")
            return 0
        if mode == "warn":
            print(f"WARN (would block): {verdict.reason}")
            return 0
        print(f"BLOCK: {verdict.reason}")
        return 1

    if not verdict.ok and mode == "warn":
        print(f"WARN (would block, running anyway — warn mode): {verdict.reason}", file=sys.stderr)
        segs = verdict.segments or (
            [tuple(shlex.split(cmd))] if isinstance(cmd, str) else [tuple(cmd)]
        )
        profile = safe_exec.get_profile(args.profile, profile_map=profile_map)
        rc, out, err = safe_exec.run_segments(segs, profile, timeout=args.timeout, cwd=args.cwd)
    else:
        rc, out, err = safe_exec.run(
            cmd,
            args.profile,
            timeout=args.timeout,
            cwd=args.cwd,
            honor_bypass=True,
            profile_map=profile_map,
            allowed_hosts=allowed_hosts,
        )
    sys.stdout.write(out or "")
    sys.stderr.write(err or "")
    return rc


SAFE_EXEC = OpSpec(
    add_args=add_safe_exec_args,
    call=call_safe_exec,
    help="Validate/run commands under safe_exec profiles from config",
)
