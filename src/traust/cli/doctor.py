#!/usr/bin/env python3
"""Environment preflight for the harness (VVAH comparative plan P8).

One command that answers "why doesn't my session work" before an hour
is lost to it. The required half is core's preflight — the same
`Context.preflight` the engine's start gate runs on the pack's enabled
assets, so doctor and the runtime refuse on the same findings (a
required gap is FAIL, never WARN) — plus the environment around it:
traust-core's store and provider readiness (in-process, SQLite by
default), the effective traust.yaml with each value's source, the
convention paths the fail-loud plan keeps soft (shown as defaults in
use), venv + locked deps, the tree-sitter grammars, VPN reachability,
and the harness's own gates.

Usage:
  traust admin doctor            # full report
  traust admin doctor --quick    # skip network checks

Exit 0 = all required checks pass (warnings allowed); 1 otherwise.
Deterministic output; safe to run anytime (read-only, no mutations).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pydantic
import pydantic_core
import yaml
from traust_core.v1.context import Config, Context, resolve_config_home, validate_config
from traust_core.v1.context.config import CONFIG_FILE
from traust_core.v1.context.home import TRAUST_CONFIG_HOME_ENV
from traust_core.v1.context.preflight import preflight_findings
from traust_core.v1.context.tools import bicep_candidates
from traust_core.v1.errors import DeploymentConfigMissing, TraustError
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.operations import Requirement

from traust.context import add_config_home_arg, feeds_cache_dir, load
from traust.paths import HARNESS_ROOT, SECURITY_PACK_DIR, skill_dir

HARNESS = HARNESS_ROOT

OK, WARN, FAIL = "ok", "warn", "FAIL"

PACK_ASSETS = SECURITY_PACK_DIR / "assets.yaml"

# (name, required) — pinned external tools per docs/external-dependencies.md
TOOLS = [
    ("git", True),
    ("jq", True),
    ("python3", True),
    ("opengrep", False),
    ("gitleaks", False),
    ("osv-scanner", False),
    ("syft", False),
    ("grype", False),
    ("skopeo", False),
    ("checkov", False),
    ("podman", False),
    ("oc", False),
    ("tokei", False),
]


# Reachability probes for a private network the harness needs (a forge on a
# VPN, an internal registry). Deployment-specific, so it is configured, not
# baked in: HARNESS_VPN_PROBES="host:port,host:port". Empty = skip the check.
def _vpn_probes() -> list[tuple[str, int]]:
    raw = os.environ.get("HARNESS_VPN_PROBES", "").strip()
    probes = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        host, _, port = item.rpartition(":")
        if host and port.isdigit():
            probes.append((host, int(port)))
    return probes


VPN_PROBES = _vpn_probes()


def _run(argv, timeout=30):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_core(results, config_home, network=True) -> Context | None:
    """traust-core in-process: the store answers a read, each registered provider's readiness
    (ProviderCatalog.readiness; without `network`, the feed sources' probes are skipped) and the
    route matrices' grammars (CodeFactsService.grammar_readiness). Returns the loaded Context
    for the checks that need it, or None when the store is not reachable."""
    try:
        core = load(config_home)
        core.services().portfolio.list_products(PageRequest(limit=1))
    except (SystemExit, TraustError, OSError) as e:
        results.append((FAIL, f"traust-core store not reachable — {e or 'traust.yaml invalid'}"))
        return None
    results.append((OK, "traust-core store reachable"))
    for binding in core.services().catalog.readiness(None, network=network):
        name = f"{binding.capability.kind.value} {binding.capability.name}"
        if binding.readiness.ready:
            results.append((OK, f"provider {name} ready"))
        else:
            results.append((WARN, f"provider {name} not ready — {binding.readiness.detail}"))
    for language, ready in core.services().code_facts.grammar_readiness().items():
        if ready.ready:
            results.append((OK, f"{language} grammar loads"))
        else:
            results.append((WARN, f"{ready.detail}; its routes are a coverage gap"))
    return core


def pack_requirements(path: Path | None = None) -> list[Requirement]:
    """The `requires:` blocks of the pack's enabled assets — what the engine's start gate
    preflights and doctor reports; `enabled: false` is the only way to keep an asset in the
    pack without its requirements."""
    raw = yaml.safe_load((path or PACK_ASSETS).read_text())
    validate_config("pack", raw)
    return [
        Requirement(**asset["requires"])
        for asset in raw["assets"].values()
        if asset.get("enabled") is not False and asset.get("requires")
    ]


def check_preflight(results, core) -> None:
    """`Context.preflight` on the pack's enabled assets: the same findings the engine's start
    gate refuses on. Every gap names its fix and is FAIL, never WARN."""
    core.register_feeds()
    findings = preflight_findings(core, pack_requirements())
    for finding in findings:
        results.append((FAIL, finding))
    if not findings:
        results.append((OK, "preflight: every enabled asset's requirements are met"))


def check_defaults(results, core) -> None:
    """The convention paths the fail-loud plan keeps soft: where each resolves from, so a
    default in use is visible (a documented convention, never inferred from absence)."""
    try:
        cache = feeds_cache_dir(core)
    except DeploymentConfigMissing as e:
        results.append((WARN, f"feeds cache: unresolved — {e}"))
    else:
        source = (
            "env FEEDS_CACHE_DIR"
            if os.environ.get("FEEDS_CACHE_DIR")
            else "traust.yaml locations.feeds_cache"
            if core.config.locations.feeds_cache
            else "default <progress_tracker>/feeds"
        )
        results.append((OK, f"feeds cache: {cache} ({source})"))
    extra = [h.strip() for h in os.environ.get("GIT_HOSTS", "").split(",") if h.strip()]
    results.append(
        (
            OK,
            "extra forges (GIT_HOSTS): "
            + (", ".join(extra) if extra else "none — github.com/gitlab.com only"),
        )
    )
    env = os.environ.get("CCA_BICEP")
    on_path = shutil.which("bicep")
    found = next((p for p in bicep_candidates() if p.is_file()), None)
    if found is None:
        results.append(
            (
                WARN,
                "bicep: none of $CCA_BICEP, PATH or the pinned ~/.cache/cca-tools dir "
                "resolves — cloud-config-audit needs one",
            )
        )
    else:
        source = (
            "$CCA_BICEP"
            if env and found == Path(env)
            else "PATH"
            if on_path and found == Path(on_path)
            else "pinned dir"
        )
        results.append((OK, f"bicep: {found} ({source})"))


# Environment overrides traust.context honours over the file (its sanctioned list).
_ENV_LOCATIONS = {
    "locations.analysis_results": "AUDIT_RESULTS_ROOT",
    "locations.feeds_cache": "FEEDS_CACHE_DIR",
}
SHIPPED_FILES = ("external-tools.yaml", "safe-exec-profiles.yaml", "feeds.yaml")


def _render(key: str, value: object) -> str:
    if key == "database.url" and value and (password := urlsplit(str(value)).password):
        value = str(value).replace(f":{password}@", ":***@")
    return json.dumps(pydantic_core.to_jsonable_python(value))


def check_config(results, config_home):
    """Every effective traust.yaml value and where it came from: the file, the environment or
    core's default. The shipped files are traust-core's, never the adopter's."""
    home = resolve_config_home(config_home)
    path = home / CONFIG_FILE if home is not None else None
    found = path is not None and path.is_file()
    try:
        raw = (yaml.safe_load(path.read_text()) or {}) if found else {}
        config = Config.from_home(home)
    except (OSError, yaml.YAMLError, TraustError) as e:
        results.append((FAIL, f"{CONFIG_FILE} not loadable — {e}"))
        return
    results.append((OK, f"config file: {path if found else 'none (zero-config defaults)'}"))
    for name, value in config:
        fields = value if isinstance(value, pydantic.BaseModel) else [(None, value)]
        for sub, leaf in fields:
            key = f"{name}.{sub}" if sub else name
            in_file = sub in (raw.get(name) or {}) if sub else name in raw
            source = "file" if in_file else "default"
            if (var := _ENV_LOCATIONS.get(key)) and os.environ.get(var):
                leaf, source = os.environ[var], f"env {var}"
            elif key.endswith("_env") and isinstance(leaf, str):
                source += f", {leaf} {'set' if os.environ.get(str(leaf)) else 'UNSET'}"
            results.append((OK, f"config {key} = {_render(key, leaf)} ({source})"))
    for name in SHIPPED_FILES:
        results.append((OK, f"config {name}: shipped with traust-core (not configurable)"))


def check_python(results):
    venv = HARNESS / ".venv"
    if (venv / "bin" / "python").exists():
        results.append((OK, ".venv present"))
    else:
        results.append(
            (
                WARN,
                ".venv missing — create it and install with --require-hashes -r requirements.lock",
            )
        )
    if (HARNESS / "requirements.lock").is_file():
        results.append((OK, "requirements.lock present (hash-locked)"))
    else:
        results.append((FAIL, "requirements.lock missing"))
    try:
        import jsonschema  # noqa: F401

        results.append((OK, "jsonschema importable"))
    except ImportError:
        results.append(
            (
                FAIL,
                "jsonschema not importable — report validation and the pqc-facts gate will not run",
            )
        )


def check_tools(results):
    for name, required in TOOLS:
        path = shutil.which(name)
        if path:
            results.append((OK, f"tool {name} on PATH"))
        else:
            results.append(
                (
                    FAIL if required else WARN,
                    f"tool {name} not found"
                    + ("" if required else " (skills that need it will skip/fail)"),
                )
            )
    binsha = skill_dir("pqc-readiness") / "bin"
    if (binsha / "pqc-scan").exists() and (binsha / "pqc-scan.sha256").exists():
        r = _run(["shasum", "-a", "256", str(binsha / "pqc-scan")])
        want = (binsha / "pqc-scan.sha256").read_text().split()[0]
        got = r.stdout.split()[0] if r and r.returncode == 0 else ""
        results.append(
            (
                OK if got == want else FAIL,
                "pqc-scan binary sha "
                + (
                    "matches recorded build"
                    if got == want
                    else "MISMATCH vs recorded build — rebuild via build_pqc_scan.sh"
                ),
            )
        )
    else:
        results.append(
            (
                WARN,
                "pqc-scan binary not built (pqc-readiness "
                "Layer 1 unavailable until build_pqc_scan.sh)",
            )
        )


def check_network(results):
    if not VPN_PROBES:
        results.append(
            (
                WARN,
                "no private-network probes configured — set "
                "HARNESS_VPN_PROBES=host:port,... if any skill needs "
                "one (unconfigured is not the same as reachable)",
            )
        )
    for host, port in VPN_PROBES:
        try:
            with socket.create_connection((host, port), timeout=5):
                results.append((OK, f"VPN reachability: {host}:{port}"))
        except OSError:
            results.append(
                (WARN, f"cannot reach {host}:{port} — VPN down? (internal skills will fail)")
            )


def check_gates(results):
    for module, label, quiet in (
        ("traust.cli.check_skill_alignment", "alignment gate", False),
        ("traust.cli.check_skill_security", "security gate", True),
        ("traust.cli.check_docs_consistency", "docs gate", False),
    ):
        r = _run([sys.executable, "-m", module] + (["--quiet"] if quiet else []), timeout=120)
        if r is None:
            results.append((WARN, f"{label}: could not run"))
        elif r.returncode == 0:
            results.append((OK, f"{label}: green"))
        else:
            results.append((FAIL, f"{label}: FAILING on this tree — commits will be blocked"))
    hooks = _run(["git", "-C", str(HARNESS), "config", "core.hooksPath"])
    if hooks and hooks.stdout.strip() == ".githooks":
        results.append((OK, "git hooks enabled (.githooks)"))
    else:
        results.append((WARN, "git hooks NOT enabled — run: git config core.hooksPath .githooks"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_config_home_arg(ap)
    ap.add_argument(
        "--quick", action="store_true", help="skip network checks (the feed sources' probes too)"
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    # Core's preflight audits the home the environment resolves; the CLI flag has to win there
    # too, or doctor could report a different home than the one it loaded.
    saved = os.environ.get(TRAUST_CONFIG_HOME_ENV)
    if args.config_home is not None:
        os.environ[TRAUST_CONFIG_HOME_ENV] = str(args.config_home)
    try:
        results: list[tuple[str, str]] = []
        core = check_core(results, args.config_home, network=not args.quick)
        if core is not None:
            check_preflight(results, core)
            check_defaults(results, core)
        check_config(results, args.config_home)
        check_python(results)
        check_tools(results)
        if not args.quick:
            check_network(results)
        check_gates(results)

        fails = [m for s, m in results if s == FAIL]
        if args.json:
            print(json.dumps([{"status": s, "check": m} for s, m in results], indent=1))
        else:
            print(f"harness doctor — {HARNESS}")
            for s, m in results:
                icon = {"ok": "✓", "warn": "~", "FAIL": "✗"}[s]
                print(f"  {icon} {m}")
            summary = (
                "✗ " + str(len(fails)) + " required check(s) failing"
                if fails
                else "✓ environment ready"
            )
            print(f"\n{summary}")
        return 1 if fails else 0
    finally:
        if args.config_home is not None:
            if saved is None:
                os.environ.pop(TRAUST_CONFIG_HOME_ENV, None)
            else:
                os.environ[TRAUST_CONFIG_HOME_ENV] = saved


if __name__ == "__main__":
    sys.exit(main())
