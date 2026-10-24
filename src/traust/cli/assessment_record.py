"""``traust reporting record``: an audit document as an assessment of the audited commit.

traust-core publishes the document (its contract schema is the gate) and records the
assessment; the same document of the same kind on the same commit at the same time is one run.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, time
from importlib.metadata import version
from pathlib import Path

from traust_core.v1.models.artifacts import (
    ArtifactDocument,
    IsolationReviewArtifact,
    PrivProfileArtifact,
    SecurityAuditArtifact,
    VulnFindingsArtifact,
)
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import parser, run, when
from traust.context import load_core

# The kind of assessment each audit skill records, and its document's contract type.
RECORDS: dict[AssessmentKind, tuple[str, type[ArtifactDocument]]] = {
    AssessmentKind.CONTAINER: ("secure-container-audit", SecurityAuditArtifact),
    AssessmentKind.RPM: ("secure-rpm-audit", SecurityAuditArtifact),
    AssessmentKind.ISOLATION_REVIEW: ("isolation-review", IsolationReviewArtifact),
    AssessmentKind.PRIV_PROFILE: ("operator-priv-profile", PrivProfileArtifact),
    AssessmentKind.VULN_SCAN: ("vuln-scan", VulnFindingsArtifact),
    AssessmentKind.SECURE_CODE: ("secure-code-audit", SecurityAuditArtifact),
}


def ran_at(kind: AssessmentKind, doc: ArtifactDocument) -> datetime:
    """When the audit ran, so re-recording a document is the same run."""
    if kind is AssessmentKind.PRIV_PROFILE:
        return datetime.now(UTC)  # a profile states no run time: each record is a new run
    if kind is AssessmentKind.ISOLATION_REVIEW and (reviewed := when(doc.metadata.reviewed_at)):
        return reviewed
    if kind is AssessmentKind.VULN_SCAN:
        return when(doc.scanned_at)  # schema: required, a time with a zone
    return datetime.combine(date.fromisoformat(doc.metadata.date), time(), UTC)  # schema: a date


def main(argv: list[str] | None = None) -> int:
    ap = parser("reporting", "record", "Record an audit document as an assessment of a commit.")
    ap.add_argument("document", type=Path, help="the audit's JSON document")
    ap.add_argument("--kind", required=True, choices=[k.value for k in RECORDS])
    ap.add_argument("--repo-url", required=True, help="https URL of the audited repository")
    ap.add_argument("--sha", required=True, help="the audited commit")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    args = ap.parse_args(argv)
    kind = AssessmentKind(args.kind)
    skill, artifact = RECORDS[kind]

    def call() -> dict:
        doc = artifact.parse(args.document.read_bytes())
        core = load_core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)
        assessment = services.assessment.record(
            doc,
            ref.id,
            kind,
            f"skill:{skill}",
            version("traust"),
            Provenance(
                run_id=uuid.uuid4(),
                source=SourceType.VULN_SCAN_REPORT,
                occurred_at=ran_at(kind, doc),
            ),
        )
        return assessment.model_dump(mode="json", exclude_none=True)

    return run(call)
