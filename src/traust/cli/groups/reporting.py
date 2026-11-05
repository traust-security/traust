"""``traust reporting …`` — report validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from traust_core.v1.errors import TraustError, ValidationError
from traust_core.v1.models.artifacts import (
    CloudConfigAuditArtifact,
    RenderFormat,
    ReportArtifact,
    ThreatModelArtifact,
)

from traust.cli.groups._registry import OpSpec, passthrough_op
from traust.context import load


def add_validate_args(ap) -> None:
    ap.add_argument("path", help="Path to a .json file or directory containing .json files")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict mode (additional warnings)",
    )
    ap.add_argument(
        "--schema",
        default=None,
        help="Schema file to validate against (default: filename-based auto-detection)",
    )
    ap.add_argument(
        "--canonical-write",
        action="store_true",
        help="Also enforce the named schema's canonical_write contract for new output "
        "(requires --schema; omit for historical reads)",
    )
    ap.add_argument(
        "--signing-pubkey",
        type=Path,
        help="cosign public key for historical findings-layer Merkle/signature verification",
    )


def _print_result(result) -> None:
    name = Path(result.file_path).name
    if result.passed and not result.warnings:
        print(f"  PASS  {name}")
        return
    parts = [f"{len(result.errors)} error(s)"] if result.errors else []
    if result.warnings:
        parts.append(f"{len(result.warnings)} warning(s)")
    print(f"  {'PASS' if result.passed else 'FAIL'}  {name} ({', '.join(parts)})")
    for e in result.errors:
        print(f"        ERROR: {e}")
    for w in result.warnings:
        print(f"        WARN:  {w}")


def call_validate(args) -> int:
    # `--schema` names a contract schema by its file name (`triage.schema.json`) or bare name.
    schema = None if args.schema is None else Path(args.schema).name.removesuffix(".schema.json")
    try:
        results = load(args.config_home).reporting.validate_reports(
            Path(args.path),
            strict=args.strict,
            schema=schema,
            canonical_write=args.canonical_write,
            signing_pubkey=args.signing_pubkey,
        )
    except TraustError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not results:
        target = Path(args.path)
        if target.is_dir():
            print(f"No .json files found in {target}")
        else:
            print(f"Path not found: {target}")
        return 1

    print(f"\nValidating {len(results)} report(s)...\n")
    total_errors = 0
    total_warnings = 0
    for r in results:
        _print_result(r)
        total_errors += len(r.errors)
        total_warnings += len(r.warnings)
        print()

    print("=" * 60)
    print(f"Total: {len(results)} file(s), {total_errors} error(s), {total_warnings} warning(s)")
    failed = sum(1 for r in results if not r.passed)
    if failed:
        print(f"Result: {failed} FAILED")
    else:
        print("Result: ALL PASSED")
    return 0 if not failed else 1


VALIDATE = OpSpec(
    add_args=add_validate_args,
    call=call_validate,
    help="Validate security report JSON files against contracts schemas",
)


def add_lint_args(ap) -> None:
    ap.add_argument(
        "paths",
        nargs="+",
        help="THREAT_MODEL.md files or directories (searched recursively)",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Promote optional gaps to warnings in the summary",
    )


def call_lint(args) -> int:
    try:
        results = load(args.config_home).reporting.lint_threat_models(
            [Path(p) for p in args.paths], strict=args.strict
        )
    except TraustError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not results:
        print("no THREAT_MODEL.md files found", file=sys.stderr)
        return 1
    total_errors = 0
    total_warnings = 0
    failed = 0
    for r in results:
        if r.errors or r.warnings:
            print(f"\n{r.file_path}:")
            for e in r.errors:
                print(f"  ERROR: {e}")
            for w in r.warnings:
                print(f"  WARN:  {w}")
        total_errors += len(r.errors)
        total_warnings += len(r.warnings)
        if r.errors:
            failed += 1
    print(f"\n{len(results)} file(s), {total_errors} error(s), {total_warnings} warning(s)")
    if failed:
        print(f"Result: {failed} FAILED")
        return 1
    print("Result: ALL PASSED")
    return 0


LINT = OpSpec(
    add_args=add_lint_args,
    call=call_lint,
    help="Lint THREAT_MODEL.md artifacts against schema contract",
)


def add_render_args(ap) -> None:
    ap.add_argument("report", type=Path, help="Path to a security report JSON file")
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        help="Write markdown to file (default: stdout)",
    )
    ap.add_argument(
        "--allow-section-loss",
        action="store_true",
        help="Threat models: overwrite --out even if the new rendering empties or "
        "drops a section the existing file has (an intended removal)",
    )


def call_render(args) -> int:
    """A security report or (by its `-threat-model.json` name) a threat model, as Markdown; a
    document its contract schema refuses is not rendered."""
    threat_model = args.report.name.endswith("-threat-model.json")
    artifact = ThreatModelArtifact if threat_model else ReportArtifact
    try:
        reporting = load(args.config_home).reporting
        md = reporting.render(artifact.parse(args.report.read_bytes()), RenderFormat.MARKDOWN)
    except (OSError, TraustError) as e:
        print(f"render: ERROR: {e}", file=sys.stderr)
        return 2
    if args.out:
        if threat_model and args.out.exists() and not args.allow_section_loss:
            lost = reporting.lost_sections(args.out.read_text(encoding="utf-8"), md)
            if lost:
                print(
                    f"render: refusing to overwrite {args.out}: the new rendering drops "
                    f"or empties {lost}. The JSON is missing what the Markdown has -- "
                    "complete the JSON first, or pass --allow-section-loss if the "
                    "removal is intended.",
                    file=sys.stderr,
                )
                return 1
        args.out.write_text(md, encoding="utf-8")
        print(f"render: wrote {args.out}")
    else:
        print(md, end="")
    return 0


RENDER = OpSpec(
    add_args=add_render_args,
    call=call_render,
    help="Render a validated security report JSON to Markdown",
)


def add_rate_threats_args(ap) -> None:
    ap.add_argument("model", type=Path, help="Path to a <repo>-threat-model.json artifact")
    ap.add_argument(
        "--check",
        action="store_true",
        help="Report derived values that disagree with their factors; write nothing",
    )


def call_rate_threats(args) -> int:
    """Fill each OWASP risk_rating's derived values from its factors.

    The author scores the factors (and optionally the basis and one reason
    per factor); the means, levels and severity are arithmetic, so this
    computes them with traust-core's risk_rating rather than leaving
    them to the author. Threats without a risk_rating are left alone.
    """
    from traust_core.v1.models.values import risk_rating

    document = json.loads(args.model.read_text(encoding="utf-8"))
    changed, failed = [], []
    for threat in document.get("threats") or []:
        rating = threat.get("risk_rating")
        if not rating:
            continue
        tid = threat.get("id", "?")
        impact = rating.get("impact") or {}
        try:
            rebuilt = risk_rating.rate(
                (rating.get("likelihood") or {}).get("factors") or {},
                impact.get("technical") or {},
                impact.get("business"),
                basis=impact.get("basis"),
                rationale=rating.get("rationale"),
            )
        except ValueError as exc:
            failed.append(f"{tid}: {exc}")
            continue
        if rebuilt != rating:
            changed.append(tid)
            threat["risk_rating"] = rebuilt
    for line in failed:
        print(f"rate-threats: {line}", file=sys.stderr)
    if args.check:
        for tid in changed:
            print(f"rate-threats: {tid} derived values disagree with its factors")
        return 1 if (changed or failed) else 0
    if changed and not failed:
        args.model.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(
        f"rate-threats: {len(changed)} rating(s) updated, {len(failed)} error(s)"
        + (" -- nothing written" if failed else "")
    )
    return 1 if failed else 0


RATE_THREATS = OpSpec(
    add_args=add_rate_threats_args,
    call=call_rate_threats,
    help="Fill OWASP risk ratings' scores, levels and severity from their factors",
)


def add_sarif_args(ap) -> None:
    ap.add_argument(
        "reports",
        nargs="*",
        type=Path,
        help="report(s): *-security-audit.json, *-container-audit.json, "
        "*-cloud-config-audit.json, or *-findings-current.json",
    )
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        help="output path (single input only; default: <input stem>.sarif alongside input)",
    )
    ap.add_argument(
        "--results-root",
        type=Path,
        help="batch sweep: walk this tree for exportable reports; requires --out-dir",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        help="sweep output tree — .sarif files mirror reports' relative paths",
    )
    ap.add_argument("--compact", action="store_true", help="minified JSON")


def call_sarif(args) -> int:
    if bool(args.results_root) == bool(args.reports):
        print("ERROR: pass report paths OR --results-root, not both/neither", file=sys.stderr)
        return 2
    if args.results_root and not args.out_dir:
        print("ERROR: --results-root requires --out-dir", file=sys.stderr)
        return 2
    if args.out and (len(args.reports) > 1 or args.results_root):
        print("ERROR: -o/--out requires exactly one input report", file=sys.stderr)
        return 2

    reporting = load(args.config_home).reporting
    sweep_root = None
    report_paths = list(args.reports)
    if args.results_root:
        sweep_root = args.results_root.resolve()
        report_paths = reporting.sarif_reports(sweep_root)
        if not report_paths:
            print(f"no exportable reports under {sweep_root}")
            return 0

    rc = 0
    for report_path in report_paths:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {report_path}: {e}", file=sys.stderr)
            rc = 1
            continue
        if not isinstance(report, dict) or "findings" not in report:
            print(f"ERROR: {report_path}: not a harness report (no findings key)", file=sys.stderr)
            rc = 1
            continue
        # by content, not name: a cloud-config cumulative is a -findings-current.json
        metadata = report.get("metadata") or {}
        declared = metadata.get("assessment_mode") == "declared" or "facts_ref" in metadata
        artifact = CloudConfigAuditArtifact if declared else ReportArtifact
        try:
            sarif_doc = reporting.sarif(artifact.from_document(report))
        except ValidationError as e:
            print(f"ERROR: {report_path}: {e}", file=sys.stderr)
            rc = 1
            continue
        sarif_name = (
            report_path.name[: -len(".json")] + ".sarif"
            if report_path.name.endswith(".json")
            else report_path.name + ".sarif"
        )
        if sweep_root is not None:
            rel = report_path.resolve().parent.relative_to(sweep_root)
            out = args.out_dir / rel / sarif_name
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            out = args.out or report_path.with_name(sarif_name)
        indent = None if args.compact else 2
        out.write_text(
            json.dumps(sarif_doc, indent=indent, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        n = len(sarif_doc["runs"][0]["results"])
        print(f"wrote {out} ({n} result{'s' if n != 1 else ''})")
    return rc


SARIF = OpSpec(
    add_args=add_sarif_args,
    call=call_sarif,
    help="Export harness reports to SARIF 2.1.0",
)

RECORD = passthrough_op(
    "assessment_record", "Record an audit document as an assessment of a commit."
)
