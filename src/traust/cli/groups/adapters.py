"""``traust adapters …`` — scanner adapter CLIs (opengrep, govulncheck)."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from importlib.metadata import version
from pathlib import Path

from traust_core.v1.context import Context
from traust_core.v1.context.tool_reports import (
    gitleaks_report,
    govulncheck_report,
    joern_report,
    k8s_hardening_report,
    opengrep_report,
    osv_report,
    osv_sbom_report,
    yara_report,
)
from traust_core.v1.errors import ConfigError, IntegrityError, ValidationError

from traust.cli.groups._registry import OpSpec, passthrough_op
from traust.context import load


def add_opengrep_args(ap) -> None:
    ap.add_argument("target", help="Checkout directory to scan.")
    ap.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Rules source (path | git URL[@SHA] | p/<pack>). Repeatable.",
    )
    ap.add_argument("--out", help="Output file (default: <target-basename>-opengrep.json).")
    ap.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Overall scan timeout in seconds (default 900).",
    )
    ap.add_argument(
        "--rule-allow",
        default=None,
        help="Restrict emitted findings to these bare rule ids (comma list or @file).",
    )
    ap.add_argument(
        "--rule-pack",
        type=Path,
        default=None,
        help="Default traust rule pack (default: locations.opengrep_rules, bundled)",
    )
    ap.add_argument("--opengrep", default="opengrep", help="opengrep binary (default: from PATH).")


def call_opengrep(args) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    if not shutil.which(args.opengrep):
        print(
            f"opengrep not found on PATH ({args.opengrep}) — install from "
            "https://github.com/opengrep/opengrep/releases",
            file=sys.stderr,
        )
        return 1
    try:
        report = opengrep_report(
            load(args.config_home),
            target,
            args.rules,
            pack=args.rule_pack,
            rule_allow=args.rule_allow,
            timeout=args.timeout,
            binary=args.opengrep,
        )
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except (ValidationError, IntegrityError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except TimeoutError:
        print(f"opengrep timed out after {args.timeout}s", file=sys.stderr)
        return 1
    except RuntimeError:
        print("opengrep produced no JSON", file=sys.stderr)
        return 1

    facts = report["facts"]
    errors = report["errors"]
    out = Path(args.out) if args.out else Path(f"{target.name}-opengrep.json")
    out.write_text(json.dumps(report, indent=2))
    by_sev: dict[str, int] = {}
    for f in facts:
        by_sev[f["severity_hint"]] = by_sev.get(f["severity_hint"], 0) + 1
    print(
        f"run_opengrep: {len(facts)} fact(s) {by_sev or ''} across "
        f"{report['stats']['files_scanned']} file(s); "
        f"{len(errors)} engine error(s), "
        f"{report['stats']['skipped_rules']} skipped rule(s)"
    )
    print(f"  rules: {', '.join(r['source'] for r in report['rules'])}")
    print(f"  report: {out}")
    return 0


OPENGREP = OpSpec(
    add_args=add_opengrep_args,
    call=call_opengrep,
    help="Opengrep pre-scan: normalized semantic-pattern facts",
)


def add_govulncheck_args(ap) -> None:
    ap.add_argument(
        "--repo",
        required=True,
        type=Path,
        help="target repo clone at the pinned audit SHA (read-only)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output JSON (default: ./<repo-basename>-govulncheck.json)",
    )
    ap.add_argument(
        "--timeout", type=int, default=900, help="scan timeout in seconds (default 900)"
    )
    ap.add_argument(
        "--govulncheck", default="govulncheck", help="govulncheck binary (default: from PATH)"
    )


def call_govulncheck(args) -> int:
    repo = args.repo.resolve()
    if not (repo / "go.mod").exists() and not list(repo.glob("*/go.mod")):
        print(
            f"ERROR: no go.mod under {repo} — govulncheck stage only applies to Go modules",
            file=sys.stderr,
        )
        return 1

    out = args.out or Path.cwd() / f"{repo.name}-govulncheck.json"
    try:
        doc = govulncheck_report(
            load(args.config_home),
            repo,
            timeout=args.timeout,
            binary=args.govulncheck,
            harness_version=version("traust"),
        )
    except ConfigError as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    summary = doc["summary"]
    candidates = doc["candidates"]
    print(f"wrote {out}")
    print(
        f"  {len(candidates)} advisories: "
        f"{summary['symbol_reachable']} symbol-reachable, "
        f"{summary['package_imported_not_observed']} imported-not-observed, "
        f"{summary['module_required_not_observed']} module-only"
    )
    return 0


GOVULNCHECK = OpSpec(
    add_args=add_govulncheck_args,
    call=call_govulncheck,
    help="Govulncheck reachability pre-scan for Go modules",
)


# ---------------------------------------------------------------------------
# checkov (K8s hardening / scan_k8s_hardening)
# ---------------------------------------------------------------------------


def add_checkov_args(ap) -> None:
    ap.add_argument("target", help="Checkout directory to scan.")
    ap.add_argument("-o", "--out", help="Output JSON (default: <basename>-k8s-hardening.json).")
    ap.add_argument(
        "--summary",
        action="store_true",
        help="Print per-check counts instead of writing JSON",
    )


def call_checkov(args) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    report = k8s_hardening_report(target)
    if args.summary:
        print(f"scan_k8s_hardening: {len(report['results'])} fact(s)")
        for check, count in report.get("summary", {}).items():
            print(f"  {check}: {count}")
        return 0
    out = Path(args.out) if args.out else Path(f"{target.name}-k8s-hardening.json")
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"checkov: {len(report['results'])} fact(s) → {out}")
    return 0


CHECKOV = OpSpec(
    add_args=add_checkov_args,
    call=call_checkov,
    help="Kubernetes hardening pre-scan (KHS-* facts)",
)


# ---------------------------------------------------------------------------
# gitleaks
# ---------------------------------------------------------------------------


def add_gitleaks_args(ap) -> None:
    ap.add_argument("--repo", required=True, type=Path, help="Target clone")
    ap.add_argument("--out", type=Path, help="Output JSON (default: <repo>-gitleaks.json)")
    ap.add_argument(
        "--mode",
        choices=("dir", "history"),
        default="dir",
        help="dir = working tree; history = full git history",
    )
    ap.add_argument("--config", type=Path, help="gitleaks TOML (default: from context)")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--gitleaks", default="gitleaks", help="gitleaks binary")


def call_gitleaks(args) -> int:
    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    try:
        doc = gitleaks_report(
            load(args.config_home),
            repo,
            mode=args.mode,
            config=args.config,
            timeout=args.timeout,
            binary=args.gitleaks,
        )
    except (ConfigError, FileNotFoundError, RuntimeError, TimeoutError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    out = args.out or Path.cwd() / f"{repo.name}-gitleaks.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"gitleaks: {len(doc['candidates'])} candidate(s) → {out}")
    return 0


GITLEAKS = OpSpec(
    add_args=add_gitleaks_args,
    call=call_gitleaks,
    help="Gitleaks secret pre-scan candidate generator",
)


# ---------------------------------------------------------------------------
# osv — dependency advisories from the OSV API, or osv-scanner when air-gapped
# ---------------------------------------------------------------------------


def add_osv_args(ap) -> None:
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", type=Path, help="Target checkout (lockfiles and manifests)")
    target.add_argument(
        "--sbom",
        type=Path,
        help="syft JSON SBOM of a container image (syft -o syft-json): its language "
        "packages not installed by an OS package; OS packages stay with grype",
    )
    ap.add_argument(
        "--grype",
        type=Path,
        help="With --sbom: grype JSON for the same SBOM, to tag also_in_grype",
    )
    ap.add_argument("--out", type=Path, help="Output JSON (default: <repo-or-sbom>-osv.json)")
    ap.add_argument("--timeout", type=int, default=60, help="Per-request timeout, seconds")
    ap.add_argument(
        "--source",
        choices=("api", "osv-scanner"),
        default=None,
        help="Default: `feeds.osv_access` in traust.yaml — api "
        "(default: the engine's manifest parsers plus the OSV API) or air-gapped "
        "(osv-scanner offline against an adopter-provided database)",
    )
    ap.add_argument("--osv-scanner", default="osv-scanner", help=argparse.SUPPRESS)
    ap.add_argument("--no-freeze", action="store_true", help=argparse.SUPPRESS)


def _osv_core(args, source: str) -> tuple[Context, str | None, float]:
    """The Context for an osv run (the feeds registry for the API), the osv-scanner binary when
    air-gapped, and the timeout."""
    core = load(args.config_home)
    if source == "osv-scanner":
        return core, args.osv_scanner, max(args.timeout, 600)
    core.register_feeds()
    return core, None, args.timeout


def _note_unresolved_manifests() -> None:
    from traust.registry.osv_urls import deps_dev_settings

    if deps_dev_settings() is None:
        print(
            "NOTE: no deps_dev source in the feeds registry: manifests without a lockfile are "
            "not resolved",
            file=sys.stderr,
        )


def call_osv(args) -> int:
    from traust.registry.osv_urls import osv_access

    source = args.source or ("osv-scanner" if osv_access() == "air-gapped" else "api")
    if args.sbom is not None:
        return _call_osv_sbom(args, source)
    if args.grype is not None:
        print("--grype applies to --sbom only", file=sys.stderr)
        return 2
    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    core, scanner, timeout = _osv_core(args, source)
    if scanner is None:
        _note_unresolved_manifests()
    body = osv_report(core, repo, scanner=scanner, timeout=timeout, freeze=not args.no_freeze)
    prov = body["provenance"]
    doc = {
        "metadata": {
            "artifact": "osv-dependency-candidates",
            "repository": str(repo),
            "harness_version": version("traust"),
            **prov,
        },
        "candidates": body["candidates"],
    }
    out = args.out or Path.cwd() / f"{repo.name}-osv.json"
    return _write_osv_doc(doc, out)


def _call_osv_sbom(args, source: str) -> int:
    sbom = args.sbom.resolve()
    if not sbom.is_file():
        print(f"not a file: {sbom}", file=sys.stderr)
        return 2
    grype = None
    if args.grype is not None:
        try:
            grype = json.loads(args.grype.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read --grype {args.grype}: {e}", file=sys.stderr)
            return 2
    core, scanner, timeout = _osv_core(args, source)
    try:
        body = osv_sbom_report(core, args.sbom, scanner=scanner, timeout=timeout, grype=grype)
    except ValueError as e:  # not syft JSON
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    prov = body["provenance"]
    grype_os_installed = body.get("grype_os_installed")
    doc = {
        "metadata": {
            "artifact": "osv-dependency-candidates",
            "sbom": str(sbom),
            "harness_version": version("traust"),
            **prov,
        },
        "candidates": body["candidates"],
    }
    if grype_os_installed is not None:
        doc["grype_os_installed"] = grype_os_installed
    stem = sbom.name.removesuffix(".json").removesuffix(".syft")
    out = args.out or Path.cwd() / f"{stem}-osv.json"
    rc = _write_osv_doc(doc, out)
    if grype_os_installed:
        print(
            f"NOTE: {len(grype_os_installed)} grype match(es) are on language packages an OS "
            "package installed (listed under grype_os_installed): judge them by the owning "
            "package's advisory state, not the upstream advisory",
            file=sys.stderr,
        )
    if prov.get("status") != "failed":
        print(
            f"osv: {prov.get('skipped_os_installed', 0)} OS-installed language package(s) left to "
            "grype (Red Hat/distribution data); "
            + (
                f"{prov['grype_dedupe']['osv_only']} candidate(s) not reported by grype"
                if prov.get("grype_dedupe")
                else "no --grype given: duplicates of grype matches not marked"
            ),
            file=sys.stderr,
        )
    return rc


def _write_osv_doc(doc: dict, out: Path) -> int:
    prov = doc["metadata"]
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    if prov.get("status") == "failed":
        failure = prov.get("failure") or {}
        where = f" at {prov['base_url']}" if prov.get("base_url") else ""
        print(
            f"ERROR: OSV lookup failed{where} ({failure.get('status', 'error')}): "
            f"{failure.get('detail') or 'no package was answered'} — no dependency results; "
            f"this is NOT a clean scan (record a coverage gap) → {out}",
            file=sys.stderr,
        )
        return 2
    print(f"osv: {len(doc['candidates'])} candidate(s) → {out}")
    res = prov.get("resolution")
    if res:
        print(
            f"osv: deps.dev resolved {res.get('manifests_resolved', 0)} manifest(s) without a "
            f"lockfile ({res.get('packages_added', 0)} transitive package(s) added, "
            "version_basis: resolved)"
            + (
                f"; deps.dev {res['status']}: {res.get('issues') or res.get('failure')}"
                if res.get("status") != "complete"
                else ""
            ),
            file=sys.stderr,
        )
    if prov.get("transitive_coverage") == "partial":
        print(
            f"NOTE: {len(prov.get('unresolved_manifests') or [])} manifest(s) without a lockfile "
            "are still unresolved (reasons under unresolved_manifests): their transitive "
            "dependencies were not assessed (record a coverage gap)",
            file=sys.stderr,
        )
    if prov.get("status") == "degraded":
        print(
            "WARNING: degraded — "
            f"{prov.get('packages_unanswered', 0)} package(s) unanswered, "
            f"{prov.get('advisory_details_missing', 0)} advisory detail(s) missing, "
            f"{len(prov.get('manifests_unparsed') or [])} manifest(s) unparsed: "
            "unanswered packages are NOT clean (record a coverage gap)",
            file=sys.stderr,
        )
        return 3
    return 0


OSV = OpSpec(
    add_args=add_osv_args,
    call=call_osv,
    help="Dependency advisories from the OSV API, or osv-scanner offline when air-gapped",
)


# ---------------------------------------------------------------------------
# yara
# ---------------------------------------------------------------------------


def add_yara_args(ap) -> None:
    ap.add_argument("target", help="Directory tree to scan (e.g. rootfs)")
    ap.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Rules source (path | git URL@SHA). Repeatable; default pack if omitted.",
    )
    ap.add_argument("--out", type=Path, help="Output JSON (default: <basename>-yara.json)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--yara", default="yara", help="yara binary")
    ap.add_argument("--max-file-mb", type=int, default=64)


def call_yara(args) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    try:
        report = yara_report(
            load(args.config_home),
            target,
            args.rules,
            timeout=args.timeout,
            binary=args.yara,
            max_file_mb=args.max_file_mb,
        )
    except ValidationError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    out = args.out or Path.cwd() / f"{target.name}-yara.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"yara: {len(report.get('facts', []))} fact(s) → {out}")
    return 0


YARA = OpSpec(
    add_args=add_yara_args,
    call=call_yara,
    help="YARA known-malware-family signature pre-scan",
)


# ---------------------------------------------------------------------------
# joern reachability
# ---------------------------------------------------------------------------


def add_joern_args(ap) -> None:
    ap.add_argument("--repo", required=True, type=Path, help="Repository root")
    ap.add_argument("--out", required=True, type=Path, help="Output JSON artifact")
    ap.add_argument("--language", choices=("java", "c"), default="java")
    ap.add_argument(
        "--symbols",
        nargs="*",
        default=[],
        help="Vulnerable symbols (Java class#method or C function names)",
    )
    ap.add_argument(
        "--packages",
        default="",
        help="Comma-separated package prefixes to match",
    )
    ap.add_argument("--module", default="", help="Maven module id for package derivation")
    ap.add_argument("--timeout", type=int, default=1200)
    ap.add_argument("--max-sites", type=int, default=200)


def call_joern(args) -> int:
    repo = args.repo.resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    doc = joern_report(
        load(args.config_home),
        repo,
        symbols=args.symbols,
        language=args.language,
        packages=args.packages,
        module=args.module,
        timeout=args.timeout,
        max_sites=args.max_sites,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"joern-reachability: {doc['status']} → {args.out}")
    return 0


JOERN = OpSpec(
    add_args=add_joern_args,
    call=call_joern,
    help="Joern call-site reachability facts (Java/C)",
)


# crypto-analysis's doors on traust-core (traust.cli.crypto)
CRYPTO_SOURCE = passthrough_op("crypto", "A commit's crypto census (checkout + SBOM).", "source")
CRYPTO_IMAGE = passthrough_op("crypto", "An image's crypto census, by digest.", "image")
CRYPTO_CLUSTER = passthrough_op(
    "crypto", "A cluster's runtime crypto census, scope-gated.", "cluster"
)

# secure-code-audit's pre-scans on traust-core's code facts (traust.cli.code_facts)
ROUTE_GUARDS = passthrough_op("code_facts", "A checkout's route x guard matrix.", "route_guards")
GRPC_GUARDS = passthrough_op(
    "code_facts", "A checkout's gRPC service x interceptor matrix.", "grpc_guards"
)
LLM_APP = passthrough_op(
    "code_facts", "Whether a checkout is an LLM, agent or MCP application.", "llm_app"
)
CONFIG_MATRIX = passthrough_op(
    "code_facts", "A checkout's effective deployed defaults.", "config_matrix"
)
SANITIZERS = passthrough_op("code_facts", "A checkout's sanitizer-shaped functions.", "sanitizers")
FORK_LAG = passthrough_op(
    "code_facts", "A checkout's fork signals and in-range upstream advisories.", "fork_lag"
)
PRIV_PROFILE = passthrough_op(
    "code_facts", "A checkout's operator privilege profile (tiers 1-2).", "priv_profile"
)

# secure-container-audit's image doors on traust-core (traust.cli.image)
IMAGE_SBOM = passthrough_op("image", "Record an image's SBOM, keyed by digest.", "sbom")
IMAGE_PACKAGES = passthrough_op("image", "The packages an image's recorded SBOM holds.", "packages")
