#!/usr/bin/env python3
"""Toolchain management — install, check, and populate external scanner tools.

One command to get a working toolchain for any profile:

    python3 -m traust.cli.toolchain setup --profile code-audit
    python3 -m traust.cli.toolchain doctor --profile code-audit
    python3 -m traust.cli.toolchain fetch-dbs --profile code-audit

Subcommands:

  setup     Install the profile's tools (direct upstream downloads at the
            pins traust-core ships in external-tools.yaml), then populate DBs.
  doctor    Check every tool: installed? right version? DB present?
            Fail-closed: exits 1 if anything is wrong.
  fetch-dbs Populate vulnerability databases for the given profile.

Profiles match the ``consumers`` field of the tool pins traust-core ships.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from traust_core.v1.context import Context
from traust_core.v1.context.tool_reports import populatable_tools, tool_stamp, toolchain_failures
from traust_core.v1.errors import ConfigError

from traust.context import add_config_home_arg, load
from traust.paths import HARNESS_ROOT

INSTALL_SCRIPT = HARNESS_ROOT / "scripts" / "install-toolchain.sh"


_HYBRID_INSTALL: dict[str, str] = {
    "joern": (
        "brew install joern  (or download from github.com/joernio/joern/releases,"
        " requires Java 11+)"
    ),
    "skopeo": "brew install skopeo  (macOS) / dnf install skopeo  (Fedora/RHEL)",
    "yara": "brew install yara  (macOS) / build from github.com/VirusTotal/yara/releases",
    "pip-audit": "pipx install pip-audit",
    "checkov": "pipx install checkov",
}

# Installed by scripts/install-toolchain.sh straight from the upstream GitHub
# release at the pinned version — no intermediate package manager.
_DIRECT_DOWNLOAD = {"opengrep", "gitleaks", "syft", "grype", "cosign", "govulncheck"}


def _all_tools(core: Context) -> list[dict]:
    return [pin.model_dump() for pin in core.toolchain.pins.values()]


def _profile_tools(profile: str, core: Context) -> list[dict]:
    return [t for t in _all_tools(core) if profile in (t.get("consumers") or [])]


def _print_header(text: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}\n")


def cmd_setup(args: argparse.Namespace, core: Context) -> int:
    profile_tools = _profile_tools(args.profile, core)
    if not profile_tools:
        print(f"ERROR: no tools found for profile '{args.profile}'", file=sys.stderr)
        print(f"  Available profiles: {_available_profiles(core)}", file=sys.stderr)
        return 1

    if INSTALL_SCRIPT.is_file():
        cmd = ["bash", str(INSTALL_SCRIPT), args.profile]
        if args.dry_run:
            cmd.append("--dry-run")
        return subprocess.run(cmd).returncode

    # Fallback if script not found — advisory mode
    tool_names = [t["name"] for t in profile_tools]
    direct_tools = [n for n in tool_names if n in _DIRECT_DOWNLOAD]
    hybrid_tools = [n for n in tool_names if n not in _DIRECT_DOWNLOAD]

    _print_header(f"Toolchain setup for profile: {args.profile}")
    print(f"Tools needed: {', '.join(tool_names)}\n")

    if direct_tools:
        print(f"Step 1: Direct upstream downloads ({', '.join(direct_tools)})")
        print(f"  {INSTALL_SCRIPT} is missing — re-check the harness checkout;")
        print("  pins ship with traust-core (external-tools.yaml).")
        for name in direct_tools:
            installed = "installed" if shutil.which(name) else "MISSING"
            print(f"  [{installed}] {name}")
        print()

    if hybrid_tools:
        print(f"Step 2: Install manually ({', '.join(hybrid_tools)})")
        for name in hybrid_tools:
            instruction = _HYBRID_INSTALL.get(name, f"see docs/setup.md for {name}")
            installed = "installed" if shutil.which(name) else "MISSING"
            print(f"  [{installed}] {name}: {instruction}")
        print()

    tc = core.toolchain
    db_tools = [n for n in tool_names if n in populatable_tools()]
    if db_tools:
        print(f"Step 3: Populate vulnerability databases ({', '.join(db_tools)})")
        if not args.dry_run:
            for name in db_tools:
                if shutil.which(name):
                    _ok, msg = tc.populate(name)
                    print(f"  {msg}")
                else:
                    print(f"  {name}: skipped (not installed)")
        else:
            print("  (dry-run: skipping DB population)")
        print()

    print("Step 4: Verifying...")
    return cmd_doctor(args, core)


def cmd_doctor(args: argparse.Namespace, core: Context) -> int:
    tc = core.toolchain
    profile_tools = _profile_tools(args.profile, core)
    if not profile_tools:
        print(f"ERROR: no tools found for profile '{args.profile}'", file=sys.stderr)
        print(f"  Available profiles: {_available_profiles(core)}", file=sys.stderr)
        return 1

    _print_header(f"Toolchain doctor for profile: {args.profile}")

    all_ok = True
    results = []
    for spec in profile_tools:
        check = tc.check(spec["name"])
        results.append(check)

        if not check.installed:
            status = "MISSING"
            detail = _install_hint(spec["name"])
            all_ok = False
        elif not check.version_ok:
            status = "VERSION"
            detail = f"installed {check.version}, need >= {spec.get('expected')}"
            all_ok = False
        elif check.database is not None and not check.database.exists:
            status = "NO DB"
            detail = (
                f"v{check.version} ok, but vuln DB not found"
                f" — run: python3 -m traust.cli.toolchain"
                f" fetch-dbs --profile {args.profile}"
            )
            all_ok = False
        else:
            status = "OK"
            detail = tool_stamp(check)

        icon = "+" if status == "OK" else "!"
        print(f"  [{icon}] {spec['name']:20s} {status:8s} {detail}")

    print()
    if all_ok:
        print(f"All {len(results)} tools ready for profile '{args.profile}'.")
        return 0

    fails = toolchain_failures(results)
    print(f"{len(fails)} issue(s) found. To fix:\n")
    if any(not check.installed for check in results):
        print(f"  python3 -m traust.cli.toolchain setup --profile {args.profile}")
    if any(
        check.database is not None and not check.database.exists
        for check in results
        if check.installed
    ):
        print(f"  python3 -m traust.cli.toolchain fetch-dbs --profile {args.profile}")
    print()
    return 1


def cmd_fetch_dbs(args: argparse.Namespace, core: Context) -> int:
    tc = core.toolchain
    profile_tools = _profile_tools(args.profile, core)
    if not profile_tools:
        print(f"ERROR: no tools found for profile '{args.profile}'", file=sys.stderr)
        print(f"  Available profiles: {_available_profiles(core)}", file=sys.stderr)
        return 1

    tool_names = [t["name"] for t in profile_tools]
    db_tools = [t for t in tool_names if t in populatable_tools()]
    if not db_tools:
        print(f"No tools with DBs to populate in: {', '.join(tool_names)}")
        return 0

    print(f"Populating DBs for: {', '.join(db_tools)}")
    failures = []
    for tool in db_tools:
        ok, msg = tc.populate(tool)
        print(f"  {msg}")
        if not ok:
            failures.append(msg)

    if args.offline_bundle:
        import tarfile

        dirs = tc.db_cache_dirs()
        with tarfile.open(args.offline_bundle, "w:gz") as tar:
            for tool in db_tools:
                d = dirs.get(tool)
                if d and d.is_dir():
                    tar.add(str(d), arcname=tool)
        print(f"  Bundle written to {args.offline_bundle}")

    if failures:
        print(f"\n{len(failures)} failure(s)", file=sys.stderr)
        return 1
    return 0


def _install_hint(name: str) -> str:
    if name in _DIRECT_DOWNLOAD:
        return "scripts/install-toolchain.sh <profile>  (pin: traust-core external-tools.yaml)"
    return _HYBRID_INSTALL.get(name, "see docs/setup.md")


def _available_profiles(core: Context) -> str:
    profiles: set[str] = set()
    for t in _all_tools(core):
        for c in t.get("consumers") or []:
            profiles.add(c)
    return ", ".join(sorted(profiles))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m traust.cli.toolchain",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_config_home_arg(ap)
    sub = ap.add_subparsers(dest="command", required=True)

    # setup
    sp_setup = sub.add_parser(
        "setup",
        help="Install tools + populate DBs for a profile",
    )
    sp_setup.add_argument("--profile", required=True, help="e.g. secure-code-audit")
    sp_setup.add_argument("--dry-run", action="store_true", help="show what would be done")

    # doctor
    sp_doctor = sub.add_parser(
        "doctor",
        help="Check tool versions and DB status for a profile",
    )
    sp_doctor.add_argument("--profile", required=True, help="e.g. secure-code-audit")

    # fetch-dbs
    sp_fetch = sub.add_parser(
        "fetch-dbs",
        help="Populate vulnerability databases for a profile",
    )
    sp_fetch.add_argument("--profile", required=True, help="e.g. secure-code-audit")
    sp_fetch.add_argument(
        "--offline-bundle",
        type=Path,
        default=None,
        help="tar DB dirs to this path for air-gap transport",
    )

    args = ap.parse_args(argv)
    core = load(args.config_home)
    dispatch = {
        "setup": cmd_setup,
        "doctor": cmd_doctor,
        "fetch-dbs": cmd_fetch_dbs,
    }
    try:
        return dispatch[args.command](args, core)
    except ConfigError as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["admin", "toolchain", *sys.argv[1:]]))
