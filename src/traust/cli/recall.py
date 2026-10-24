"""``traust sweep benchmark-targets|build-canaries``: recall-benchmark's answer-key doors on
traust-core.

benchmark-targets  record the benchmark-targets manifest (YAML or JSON) as a new answer-key
                   version; the newest is the one scored. Duplicate target ids and held-out seeded
                   targets are refused
build-canaries     commit every canary (or seeded-fixture) source into a deterministic local repo
                   (traust-engine's materialiser) and record them as targets of a new version
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml
from traust_core.v1.models.artifacts import BenchmarkTargetArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import parser, run
from traust.context import load_engine_core, load_services


def targets(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "benchmark-targets", "Record the recall benchmark's answer key.")
    ap.add_argument("manifest", type=Path, help="benchmark-targets.yaml (the answer key)")
    args = ap.parse_args(argv)

    def call() -> dict:
        # YAML dates load as date objects; the schema wants their ISO strings
        raw = json.loads(json.dumps(yaml.safe_load(args.manifest.read_text()), default=str))
        doc = BenchmarkTargetArtifact.from_document(raw)
        result = load_services(args.config_home).detection_quality.record(doc, _provenance())
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
        core = load_engine_core(args.config_home, canaries="seeded" if args.seeded else "canaries")
        built = core.services().detection_quality.build_canaries(_provenance())
        return [
            {"target_id": c.target_id, "repo_url": c.repo.repo_url, "sha": c.repo.sha}
            for c in built
        ]

    return run(call)


def _provenance() -> Provenance:
    return Provenance(
        run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=datetime.now(UTC)
    )
