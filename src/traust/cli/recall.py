"""Recall benchmark bootstrap, targets, canary building, scoring and injection screening.

benchmark-targets  record the benchmark-targets manifest (YAML or JSON) as a new answer-key
                   version; the newest is the one scored. Duplicate target ids and held-out seeded
                   targets are refused
build-canaries     commit every canary (or seeded-fixture) source into a deterministic local repo
                   (traust-core's canary materialiser) and record them as targets of a new version
score-benchmark    score a runs dir of audit reports (``<id>/``, rerun ``<id>__rerun/``) against the
                   newest answer key, derived on demand and stored nowhere; without --runs-dir, the
                   scorecard per auditor version over the recorded benchmark audits (--markdown:
                   Core's benchmark-scorecards report and its HTML sibling)
screen-injection   screen recorded audit reports for the shape of obeyed prompt injection; every
                   signal is a human review item, never a verdict. Exit 1 when any is flagged
"""

from __future__ import annotations

import json
import uuid
from importlib.metadata import version
from pathlib import Path
from typing import cast

import yaml
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import BenchmarkTargetArtifact, ReportArtifact
from traust_core.v1.models.detection_quality import BenchmarkFilter, BenchmarkTargetId
from traust_core.v1.models.insight import BenchmarkScorecards, ViewFilter, ViewName

from traust.cli import _doors
from traust.cli._doors import parser, run
from traust.cli._report_files import report_paths, write_reports
from traust.context import load


def bootstrap(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "bootstrap-benchmark", "Harvest unadmitted recall-benchmark candidates.")
    ap.add_argument("--out", required=True, type=Path, help="candidate answer key (YAML)")
    ap.add_argument("--limit", type=int, default=100, help="maximum candidate findings")
    args = ap.parse_args(argv)

    def call() -> dict:
        quality = load(args.config_home).services().detection_quality
        doc = quality.bootstrap_benchmark(limit=args.limit)
        document = json.loads(doc.payload)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return {
            "out": str(args.out),
            "candidates": len(doc.targets),
            "held_out": sum(bool(t.held_out) for t in doc.targets),
            "admitted": sum(bool(t.admitted) for t in doc.targets),
        }

    return run(call)


def targets(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "benchmark-targets", "Record the recall benchmark's answer key.")
    ap.add_argument("manifest", type=Path, help="benchmark-targets.yaml (the answer key)")
    args = ap.parse_args(argv)

    def call() -> dict:
        # YAML dates load as date objects; the schema wants their ISO strings
        raw = json.loads(json.dumps(yaml.safe_load(args.manifest.read_text()), default=str))
        doc = BenchmarkTargetArtifact.from_document(raw)
        result = (
            load(args.config_home).services().detection_quality.record(doc, _doors.interactive())
        )
        return {"artifact_id": result.artifact_id, "version": raw.get("version")}

    return run(call)


def canaries(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "build-canaries", "Materialise canaries and record them as targets.")
    ap.add_argument(
        "--seeded",
        action="store_true",
        help="the seeded fixtures (recall-benchmark/seeded) instead of the canaries",
    )
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        core = load(args.config_home, canaries="seeded" if args.seeded else "canaries")
        built = core.services().detection_quality.build_canaries(_doors.interactive())
        return [
            {"target_id": c.target_id, "repo_url": c.repo.repo_url, "sha": c.repo.sha}
            for c in built
        ]

    return run(call)


RERUN = "__rerun"
REPORT_GLOB = "*-security-audit.json"


def score(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "score-benchmark", "Score recall-benchmark runs against the answer key.")
    ap.add_argument(
        "--runs-dir",
        type=Path,
        help="one dir per target id holding its *-security-audit.json (rerun: <id>__rerun); "
        "without it, the recorded benchmark audits are scored",
    )
    ap.add_argument(
        "--auditor-version",
        help="labels the runs dir's reports (default: this traust's version); filters the "
        "recorded audits",
    )
    ap.add_argument(
        "--include-held-out", action="store_true", help="release scoring: held-out targets too"
    )
    ap.add_argument("--out", type=Path, help="also write the result here (JSON)")
    ap.add_argument(
        "--markdown",
        type=Path,
        help="recorded audits only: write Core's benchmark-scorecards report and an HTML sibling "
        "(every auditor version, held-out targets excluded)",
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        filtered = (args.runs_dir, args.auditor_version, args.include_held_out or None)
        if args.markdown is not None and any(f is not None for f in filtered):
            raise ValidationError(
                "--markdown reports the recorded audits' scorecards view: every auditor "
                "version, held-out excluded; it takes no --runs-dir, --auditor-version or "
                "--include-held-out"
            )
        core = load(args.config_home)
        quality = core.services().detection_quality
        if args.markdown is not None:
            wanted = (args.markdown, args.markdown.with_suffix(".html"), *filter(None, [args.out]))
            paths = report_paths(wanted)
            rendered = core.services().insight.publish(ViewName.BENCHMARK_SCORECARDS, ViewFilter())
            model = cast(BenchmarkScorecards, rendered.model)
            out = {"scorecards": [c.model_dump(mode="json") for c in model.scorecards]}
            reports = dict(zip(paths, (rendered.markdown, rendered.html), strict=False))
            if args.out is not None:  # the JSON publishes with the reports, as one set
                reports[paths[2]] = json.dumps(out, indent=2) + "\n"
            write_reports(reports)
            return out
        if args.runs_dir is None:
            cards = quality.scorecards(
                BenchmarkFilter(
                    auditor_version=args.auditor_version, include_held_out=args.include_held_out
                )
            )
            out = {"scorecards": [c.model_dump(mode="json") for c in cards]}
        else:
            scored = quality.score_reports(
                _runs(args.runs_dir),
                args.auditor_version or version("traust"),
                include_held_out=args.include_held_out,
            )
            out = {
                "scorecard": scored.scorecard().model_dump(mode="json"),
                "run": scored.model_dump(mode="json"),
            }
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        return out

    return run(call)


def _runs(runs_dir: Path) -> dict[BenchmarkTargetId, list[ReportArtifact]]:
    """Each target's report, then its rerun's; a dir with no report is no run of its target."""
    if not runs_dir.is_dir():
        raise FileNotFoundError(f"{runs_dir}: no runs dir")
    dirs = sorted(p.name for p in runs_dir.iterdir() if p.is_dir())
    if orphans := [d for d in dirs if d.endswith(RERUN) and d.removesuffix(RERUN) not in dirs]:
        raise ValidationError(f"{runs_dir}: reruns {orphans} have no first run")
    runs: dict[BenchmarkTargetId, list[ReportArtifact]] = {}
    for d in (d for d in dirs if not d.endswith(RERUN)):
        first, rerun = _report(runs_dir / d), _report(runs_dir / f"{d}{RERUN}")
        if first is not None:
            runs[BenchmarkTargetId(d)] = [first] if rerun is None else [first, rerun]
    return runs


def _report(run_dir: Path) -> ReportArtifact | None:
    found = sorted(run_dir.glob(REPORT_GLOB)) if run_dir.is_dir() else []
    if len(found) > 1:
        raise FileExistsError(f"{run_dir}: {len(found)} reports; one run is one report")
    return ReportArtifact.parse(found[0].read_bytes()) if found else None


def screen(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "screen-injection", "Screen recorded audit reports for prompt injection.")
    ap.add_argument("artifact", nargs="+", type=uuid.UUID, help="a recorded audit report's id")
    args = ap.parse_args(argv)
    flagged = False

    def call() -> dict:
        nonlocal flagged
        quality = load(args.config_home).services().detection_quality
        screens = [quality.screen_injection(a) for a in args.artifact]
        flagged = any(s.flagged for s in screens)
        return {
            "screened": len(screens),
            "flagged": [s.model_dump(mode="json") for s in screens if s.flagged],
        }

    rc = run(call)
    return 1 if rc == 0 and flagged else rc
