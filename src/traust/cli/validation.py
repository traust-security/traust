"""Record machine validation evidence through core, without probing a target."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from traust_core.v1.models.artifacts import ValidationArtifact, ValidationPlanArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.validation import TargetAttestation, ValidationRecordInput

from traust.cli._doors import parser, run
from traust.context import load


def prepare(argv: list[str] | None = None) -> int:
    ap = parser("validation", "prepare", "Prepare validation inputs for one or more findings.")
    ap.add_argument(
        "--finding-id",
        required=True,
        action="append",
        dest="finding_ids",
        type=UUID,
        help="Finding UUID to validate (repeatable; each must be distinct).",
    )
    args = ap.parse_args(argv)

    def call() -> list:
        inputs = load(args.config_home).services().validation.prepare_many(tuple(args.finding_ids))
        return [item.model_dump(mode="json") for item in inputs]

    return run(call, redact=True)


def plan(argv: list[str] | None = None) -> int:
    ap = parser("validation", "plan", "Publish an immutable proposed validation plan artifact.")
    ap.add_argument("--document", required=True, type=Path, help="ValidationPlanArtifact JSON.")
    args = ap.parse_args(argv)

    def call() -> dict:
        document = ValidationPlanArtifact.parse(args.document.read_bytes())
        return load(args.config_home).services().validation.plan(document).model_dump(mode="json")

    return run(call, redact=True)


def record_report(
    report: Path,
    bindings: ValidationRecordInput,
    provenance: Provenance,
    *,
    config_home: Path | None = None,
    target_attestation: Path | None = None,
    install_failure: Path | None = None,
) -> dict:
    """Read only explicit input bytes; core owns identity, gates and persistence."""
    document = ValidationArtifact.parse(report.read_bytes())
    recording = bindings
    updates = {}
    if target_attestation is not None:
        attestation = TargetAttestation.model_validate_json(target_attestation.read_bytes())
        if recording.target_attestation is not None and recording.target_attestation != attestation:
            raise ValueError("conflicting target attestation inputs")
        updates["target_attestation"] = attestation
    if install_failure is not None:
        failure = install_failure.read_text(encoding="utf-8")
        if recording.install_failure is not None and recording.install_failure != failure:
            raise ValueError("conflicting install failure inputs")
        updates.update(install_failure=failure, install_failed=True)
    if updates:
        recording = ValidationRecordInput.model_validate({**recording.model_dump(), **updates})
    result = load(config_home).services().validation.record(document, provenance, recording)
    return result.model_dump(mode="json", exclude={"findings": {"__all__": {"rationale"}}})


def record(argv: list[str] | None = None) -> int:
    ap = parser("validation", "record", "Record a typed validation report and its source bindings.")
    ap.add_argument("--report", required=True, type=Path, help="ValidationArtifact JSON input.")
    ap.add_argument("--bindings", required=True, type=Path, help="Core ValidationRecordInput JSON.")
    ap.add_argument(
        "--provenance", required=True, type=Path, help="Actual run's core Provenance JSON."
    )
    ap.add_argument(
        "--target-attestation", type=Path, help="Full explicit preflight attestation JSON."
    )
    ap.add_argument(
        "--install-failure", type=Path, help="Retain an explicit install-failure artifact."
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        try:
            return record_report(
                args.report,
                ValidationRecordInput.model_validate_json(args.bindings.read_bytes()),
                Provenance.model_validate_json(args.provenance.read_bytes()),
                config_home=args.config_home,
                target_attestation=args.target_attestation,
                install_failure=args.install_failure,
            )
        except (ValueError, UnicodeError) as error:
            # Report and observation contents can contain credentials or hostile prose.
            from traust_core.v1.errors import ValidationError

            raise ValidationError("invalid validation recording input") from error

    return run(call, redact=True)


if __name__ == "__main__":
    import sys

    from traust.cli.__main__ import main

    raise SystemExit(main(["validation", "record", *sys.argv[1:]]))
