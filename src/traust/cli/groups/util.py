"""``traust util …`` — redact, elf, safe-exec."""

from __future__ import annotations

import datetime
import json
import os
import shlex
import stat
import sys
from pathlib import Path

from traust_core.v1.context.tool_reports import elf_report
from traust_core.v1.errors import ConfigError

from traust.cli.groups._registry import OpSpec
from traust.context import load

# SAFE_EXEC_DISABLED=<reason> runs a command unvetted, never silently: a stderr shout and a line
# in this per-user 0700 log.
BYPASS_LOG = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    / "traust-engine"
    / "safe-exec-bypass.log"
)


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


def call_redact(args) -> int:
    policy = load(args.config_home).services().redaction

    def redact(text: str) -> tuple[str, list[dict]]:
        done = policy.redact(text.encode("utf-8"))
        return done.payload.decode("utf-8"), [h.model_dump() for h in done.hits]

    if not args.paths:
        cleaned, hits = redact(sys.stdin.read())
        if args.scan_only:
            print(json.dumps(hits, indent=2))
            return 1 if hits else 0
        sys.stdout.write(cleaned)
        if hits:
            print(f"redact: {len(hits)} hit(s) on stdin", file=sys.stderr)
        return 0

    total_hits = 0
    failures = 0

    def display_path(path: Path) -> str:
        path_text = str(path).encode("utf-8", errors="backslashreplace").decode("utf-8")
        cleaned, _ = redact(path_text)
        return json.dumps(cleaned)[1:-1]

    def fail(path: Path, reason: str) -> None:
        nonlocal failures
        failures += 1
        print(f'redact: "{display_path(path)}": {reason}', file=sys.stderr)

    for raw in args.paths:
        pending = [Path(raw)]
        while pending:
            f = pending.pop()
            try:
                mode = f.lstat().st_mode
            except OSError:
                fail(f, "cannot inspect path")
                continue
            if stat.S_ISLNK(mode):
                fail(f, "symbolic link is not inspected; replace or remove it")
                continue
            if stat.S_ISDIR(mode):
                try:
                    pending.extend(sorted(f.iterdir(), reverse=True))
                except OSError:
                    fail(f, "cannot inspect directory contents")
                continue
            if not stat.S_ISREG(mode):
                fail(f, "not a regular text file; cannot inspect")
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except UnicodeError:
                fail(f, "not UTF-8 text; cannot inspect")
                continue
            except OSError:
                fail(f, "cannot read file")
                continue
            cleaned, hits = redact(text)
            if hits and not args.scan_only:
                try:
                    f.write_text(cleaned, encoding="utf-8")
                except (OSError, UnicodeError):
                    fail(f, "cannot write redacted file")
            total_hits += len(hits)
            for h in hits:
                print(f"{display_path(f)}: {h['category']} ({h['match_prefix']}…)")
    if failures:
        print(
            f"redact: incomplete; {failures} error(s), {total_hits} hit(s) "
            f"across {len(args.paths)} path(s)",
            file=sys.stderr,
        )
        return 2
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


def call_elf(args) -> int:
    path = args.binary.resolve()
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    out = elf_report(path, args.symbol, max_scan=args.max_scan_mb * 1_000_000)
    if out is None:
        print(f"not an ELF binary: {path}", file=sys.stderr)
        return 1
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
        p.add_argument("cmd", nargs="*", help="argv form (after --)")
    sub.add_parser("list-profiles", help="list configured safe_exec profiles")


def call_safe_exec(args) -> int:
    core = load(args.config_home)
    try:
        safe_exec = core.safe_exec
        if args.safe_exec_mode == "list-profiles":
            for name, profile in sorted(safe_exec.profiles.items()):
                print(
                    f"{name:18s} allow={sorted(profile.allow)} "
                    f"pipelines={profile.allow_pipelines} — {profile.description}"
                )
            return 0
        profile = safe_exec.profile(args.profile)
    except ConfigError as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        return 2

    mode = os.environ.get("SAFE_EXEC_MODE", "enforce").lower()
    if args.string is not None and args.cmd:
        print("pass either --string or argv, not both", file=sys.stderr)
        return 2
    cmd = args.string if args.string is not None else args.cmd
    if isinstance(cmd, str):
        verdict = safe_exec.vet_command_string(cmd, profile)
    else:
        verdict = safe_exec.validate_argv(list(cmd), profile)

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
    elif bypass := os.environ.get("SAFE_EXEC_DISABLED", "").strip():
        _log_bypass(cmd, args.profile, bypass)
    elif not verdict.ok:
        sys.stderr.write(f"[safe_exec blocked: {verdict.reason}]")
        return 126
    segments = verdict.segments or (
        [tuple(shlex.split(cmd))] if isinstance(cmd, str) else [tuple(cmd)]
    )
    rc, out, err = safe_exec.run_segments(
        segments, profile, timeout=args.timeout, cwd=Path(args.cwd) if args.cwd else None
    )
    sys.stdout.write(out or "")
    sys.stderr.write(err or "")
    return rc


def _log_bypass(cmd: str | list[str], profile: str, reason: str) -> None:
    line = f"SAFE_EXEC BYPASS profile={profile} reason={reason!r} cmd={cmd!r}"
    print(f"*** {line}", file=sys.stderr)
    try:
        BYPASS_LOG.parent.mkdir(parents=True, exist_ok=True)
        BYPASS_LOG.parent.chmod(0o700)
        with BYPASS_LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"{datetime.datetime.now().astimezone().isoformat()} {line}\n")
    except OSError:
        pass  # the stderr shout already happened


SAFE_EXEC = OpSpec(
    add_args=add_safe_exec_args,
    call=call_safe_exec,
    help="Validate/run commands under safe_exec profiles from config",
)
