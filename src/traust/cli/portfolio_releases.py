from __future__ import annotations

import csv
import tempfile
from pathlib import Path

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.release_inventory import ReleaseArtifactKind, ReleaseObservation

from traust.cli._doors import answer, parser
from traust.context import inputs_dir, load, load_caller
from traust.ops.materializers import MANUAL, _order_id
from traust.ops.releases import ReleaseDiscoveryMaterializer, ReleasePassthroughMaterializer


def discover(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio", "release-discover", "Observe inventory images and watched dist-git heads."
    )
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    materializer = ReleaseDiscoveryMaterializer(core.services(), load_caller(core))
    return answer(
        materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
    )


def passthrough(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio",
        "release-passthrough",
        "Plan container and RPM audits for release observations.",
    )
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    materializer = ReleasePassthroughMaterializer(core.services(), load_caller(core))
    return answer(
        materializer.materialize(AssetRequest(asset=materializer.asset, run_id=args.run_id))
    )


def write_batch(
    path: Path,
    kind: ReleaseArtifactKind,
    observations: tuple[ReleaseObservation, ...],
    inputs: Path,
) -> None:
    fields = (
        ("Payload Image Key(s)", "GitHub URL", "Inventory Source")
        if kind == ReleaseArtifactKind.CONTAINER
        else ("Component", "GitLab URL", "Branch", "Category", "SRPM Name", "Image Count")
    )
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(fields)
        for observation in observations:
            if kind == ReleaseArtifactKind.CONTAINER:
                writer.writerow(
                    (
                        observation.target,
                        observation.repository or "",
                        str(inputs / observation.inventory) if observation.inventory else "",
                    )
                )
            else:
                if observation.head is None:
                    raise ValidationError("RPM release observation has no pinned commit")
                writer.writerow(
                    (
                        observation.target.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git"),
                        observation.target,
                        f"commit:{observation.head}",
                        "",
                        "",
                        "",
                    )
                )


def audit(argv: list[str] | None = None) -> int:
    ap = parser(
        "portfolio", "release-audit", "Audit the exact artifact targets a release order names."
    )
    ap.add_argument("--kind", required=True, choices=tuple(ReleaseArtifactKind))
    ap.add_argument("--role", required=True)
    ap.add_argument("--run-id", default=MANUAL)
    args = ap.parse_args(argv)
    core = load(args.config_home)
    kind = ReleaseArtifactKind(args.kind)
    try:
        observations = core.services().releases.targets(kind, _order_id(args.run_id))
    except (ValueError, ValidationError):
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    except NotFoundError:
        return answer(JobResult.refused(OrderReason.NOT_FOUND))
    if not observations:
        return answer(JobResult.refused(OrderReason.NOT_FOUND))
    from traust.cli.session import run

    with tempfile.TemporaryDirectory(prefix="traust-release-audit-") as temporary:
        batch = Path(temporary) / f"{kind.value}-release.csv"
        write_batch(batch, kind, observations, inputs_dir(core))
        command = [
            "--skill",
            f"secure-{kind.value}-audit",
            "--role",
            args.role,
            "--repo",
            str(batch),
            "--run-id",
            args.run_id,
        ]
        if args.config_home is not None:
            command.extend(("--config-home", str(args.config_home)))
        return run(command)
