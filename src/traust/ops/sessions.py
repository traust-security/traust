from __future__ import annotations

import logging
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Clock, Services
from traust_core.v1.errors import ConflictError, NotFoundError, TraustError, ValidationError
from traust_core.v1.models.artifacts import ArtifactDocument, BelowRangeVerdictsArtifact
from traust_core.v1.models.base import Dto
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.integrity import sha256_hex as digest
from traust_core.v1.models.operations import (
    JobResult,
    ModelUsage,
    OrderReason,
    OrderState,
    RunOrder,
    SessionFile,
    SessionOutput,
    SessionRecord,
    SessionResult,
    SessionTask,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import recording_order_id
from traust.cli.impact import write_packets
from traust.paths import HARNESS_ROOT

log = logging.getLogger(__name__)
AUDIT = ".session-audit.json"


class PacketIndex(Dto):
    packets_assessment_id: UUID


def _prepare_below_range(services: Services, hosts: Sequence[str], root: Path, repo: str) -> None:
    url = HttpsRepoUrl.parse(repo, hosts)
    held = services.portfolio.find_repository(url)
    if held is None or held.id is None:
        raise NotFoundError("session repository is not in the inventory")
    latest = services.below_range.latest(held.id)
    services.below_range.fetch(latest.packets, root)
    write_packets(latest.packets, root, latest.assessment_id)
    (root / "adversarial-content-doctrine.md").write_bytes(
        (HARNESS_ROOT / "docs/adversarial-content-doctrine.md").read_bytes()
    )


def _record_below_range(
    services: Services,
    read_input: Callable[[str], bytes],
    doc: ArtifactDocument,
    source: Provenance | None,
    order_id: UUID | None,
) -> UUID:
    index = PacketIndex.model_validate_json(read_input("input/below-range.json"))
    if (
        not isinstance(doc, BelowRangeVerdictsArtifact)
        or UUID(doc.packets_assessment_id) != index.packets_assessment_id
    ):
        raise ValidationError("session verdicts do not name the staged packets")
    return services.below_range.record(doc, source, run_order_id=order_id).artifact_id


@dataclass(frozen=True)
class SessionDoors:
    prepare: Callable[[Services, Sequence[str], Path, str], None]
    output: str
    document: type[ArtifactDocument]
    record: Callable[
        [Services, Callable[[str], bytes], ArtifactDocument, Provenance | None, UUID | None], UUID
    ]
    models: Mapping[str, tuple[str, str | None]]


SESSIONS = {
    ("dependency-watch", "below-range"): SessionDoors(
        _prepare_below_range,
        "output/verdicts.json",
        BelowRangeVerdictsArtifact,
        _record_below_range,
        {
            "reviewer_a": ("fact-judge", "opus-class"),
            "reviewer_b": ("fact-judge", None),
            "judge": ("fact-judge", "opus-class"),
        },
    ),
}


def read_file(root: Path, relative: str) -> bytes:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {".", ".."} for p in parts):
        raise ValidationError("session file is outside the task")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValidationError("session output must be a regular file")
            return stream.read()
    finally:
        os.close(directory)


def input_files(root: Path) -> tuple[SessionFile, ...]:
    inputs = root / "input"
    if inputs.is_symlink() or not inputs.is_dir():
        raise ValidationError("session inputs must be a task directory")
    files = []
    for path in sorted(inputs.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValidationError("session inputs cannot be symlinks")
        if not path.is_dir():
            relative = path.relative_to(root).as_posix()
            payload = read_file(root, relative)
            files.append(SessionFile(path=relative, bytes=len(payload), sha256=digest(payload)))
    return tuple(files)


def usage(result: SessionResult) -> tuple[ModelUsage, ...]:
    return tuple(
        ModelUsage(
            provider=value.provider,
            model=value.model,
            occurred_at=value.occurred_at,
            tokens_in=value.tokens_in,
            tokens_out=value.tokens_out,
            cache_read=value.cache_read if value.cache_read is not None else 0,
            cache_creation=value.cache_creation if value.cache_creation is not None else 0,
            skill=value.skill,
            session=value.session,
        )
        for value in result.usage
    )


def leased_session_order(
    services: Services, clock: Clock, order_id: UUID, worker: WorkerId, lease_generation: int
) -> RunOrder:
    """Preflight the supplied claim; never obtain authority from the order being inspected."""
    order = services.ops.get(order_id)
    if (
        not worker
        or type(lease_generation) is not int
        or lease_generation < 1
        or order.state != OrderState.LEASED
        or order.lease_holder != worker
        or order.lease_generation != lease_generation
        or order.lease_expires_at is None
        or order.lease_expires_at <= clock.now()
    ):
        raise ConflictError("session order is not leased to this worker and generation")
    return order


class SessionRunner:
    def __init__(
        self,
        services: Services,
        clock: Clock,
        resolve: Callable[[str, str | None], str],
        hosts: Sequence[str],
        osv_access: str,
    ) -> None:
        self._services, self._clock, self._resolve = services, clock, resolve
        self._hosts, self._osv_access = tuple(hosts), osv_access

    def prepare(
        self,
        skill: str,
        mode: str,
        repo: str,
        root: Path,
        order_id: UUID | None = None,
        worker: WorkerId | None = None,
        args: Sequence[str] = (),
        *,
        lease_generation: int | None = None,
        persist_binding: bool = True,
    ) -> tuple[SessionTask, SessionRecord]:
        doors = SESSIONS.get((skill, mode))
        if doors is None:
            raise ValidationError("session mode is not registered")
        if self._osv_access == "air-gapped":
            raise ValidationError("below-range requires OSV API access")
        self._lease(order_id, worker, lease_generation, repo)
        models = {slot: self._resolve(role, tier) for slot, (role, tier) in doors.models.items()}
        root = root.resolve()
        if root.exists() and any(root.iterdir()):
            raise ValidationError("session task directory must be empty")
        (root / "input").mkdir(parents=True, exist_ok=True)
        (root / "output").mkdir()
        doors.prepare(self._services, self._hosts, root / "input", repo)
        files = input_files(root)
        task = SessionTask.from_document(
            {
                "schema_version": "1",
                "run_id": str(order_id) if order_id else None,
                **({"lease_generation": lease_generation} if lease_generation is not None else {}),
                "skill": skill,
                "mode": mode,
                "args": [repo, *args],
                "models": models,
                "input": [file.path for file in files],
                "output": {"path": doors.output, "schema": doors.document.schema},
            }
        )
        (root / "task.json").write_bytes(task.payload)
        audit = SessionRecord(
            lease_generation=lease_generation,
            skill=skill,
            mode=mode,
            executor_session=None,
            models=models,
            task_sha256=digest(task.payload),
            inputs=files,
            output=SessionOutput(path=doors.output, sha256=None, artifact_id=None),
        )
        if persist_binding and order_id is not None:
            # Split prepare/record processes share no trusted memory. Pin the complete
            # staging receipt in the DB; two mutually consistent local files are not proof.
            assert worker is not None and lease_generation is not None
            self._services.ops.record_session(
                order_id, worker, audit, lease_generation=lease_generation
            )
        elif order_id is not None:
            # Fetching inputs can outlast the lease. Do not start an executor on a stale claim.
            self._lease(order_id, worker, lease_generation, repo)
        (root / AUDIT).write_text(audit.model_dump_json())
        log.info(
            "session staged skill=%s mode=%s files=%d bytes=%d order=%s",
            skill,
            mode,
            len(files),
            sum(f.bytes for f in files),
            order_id,
        )
        return task, audit

    def task(self, root: Path) -> tuple[SessionTask, SessionRecord]:
        task = SessionTask.parse(read_file(root, "task.json"))
        audit = SessionRecord.model_validate_json(read_file(root, AUDIT))
        doors = SESSIONS.get((task.skill, task.mode))
        if (
            doors is None
            or task.output.path != doors.output
            or task.output.schema != doors.document.schema
            or audit.output.path != task.output.path
            or audit.executor_session is not None
            or audit.output.artifact_id is not None
            or audit.output.sha256 is not None
        ):
            raise ValidationError("task does not match its registered session mode")
        if (
            digest(task.payload) != audit.task_sha256
            or task.lease_generation != audit.lease_generation
            or input_files(root) != audit.inputs
            or tuple(task.input) != tuple(f.path for f in audit.inputs)
        ):
            raise ValidationError("staged session inputs changed")
        return task, audit

    def record(
        self,
        root: Path,
        result: SessionResult | None = None,
        worker: WorkerId | None = None,
        failed: bool = False,
        staged: tuple[SessionTask, SessionRecord] | None = None,
    ) -> JobResult:
        task, audit = staged if staged is not None else self.task(root)
        failed = failed or (result is not None and result.error is not None)
        order_id = UUID(task.run_id) if task.run_id is not None else None
        generation = task.lease_generation
        repo_id = self._lease(order_id, worker, generation, task.args[0] if task.args else None)
        if (
            staged is None
            and order_id is not None
            and audit not in self._services.ops.manifest(order_id).sessions
        ):
            raise ValidationError("session has no matching staged receipt for this claim")
        measured = usage(result) if result else ()
        output_digest = None

        def read_input(relative: str) -> bytes:
            # Validate the exact bytes consumed by the record door, not just an earlier
            # walk of the directory. Files in a split task need not stay put after that walk.
            data = read_file(root, relative)
            expected = next((f for f in audit.inputs if f.path == relative), None)
            if expected is None or digest(data) != expected.sha256:
                raise ValidationError("staged session input changed")
            return data

        def receipt(artifact_id: UUID | None) -> None:
            recorded = SessionRecord(
                **{
                    **audit.model_dump(),
                    "executor_session": result.session if result else None,
                    "output": SessionOutput(
                        path=task.output.path, sha256=output_digest, artifact_id=artifact_id
                    ),
                }
            )
            if order_id is None:
                print(recorded.model_dump_json())
            else:
                assert worker is not None and generation is not None
                self._services.ops.record_session(
                    order_id, worker, recorded, lease_generation=generation
                )

        outcome = JobResult.failed(OrderReason.RUNNER_CRASHED)
        try:
            payload = read_file(root, task.output.path)
            output_digest = digest(payload)
            current_task, current_audit = self.task(root)
            if current_task.payload != task.payload or current_audit != audit:
                raise ValidationError("staged session metadata changed")
            if not failed:
                doors = SESSIONS[(task.skill, task.mode)]
                doc = doors.document.parse(payload)
                source = (
                    Provenance(
                        run_id=order_id,
                        source=SourceType.IMPACT_REPORT,
                        occurred_at=self._clock.now(),
                    )
                    if order_id
                    else None
                )
                # The domain write and its success receipt share the lease transaction.
                # No external executor or input staging runs while the order is locked.
                if order_id is None:
                    guard = nullcontext()
                else:
                    assert repo_id is not None and worker is not None and generation is not None
                    guard = self._services.ops.bound(
                        order_id, repo_id, worker=worker, lease_generation=generation
                    )
                with guard:
                    artifact_id = doors.record(self._services, read_input, doc, source, order_id)
                    receipt(artifact_id)
                return JobResult.succeeded(written=(str(artifact_id),)).model_copy(
                    update={"usage": measured}
                )
        except (OSError, ValidationError) as error:
            if not failed:
                log.warning(
                    "session output refused order=%s error=%s", order_id, type(error).__name__
                )
                outcome = JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID)
        except TraustError as error:
            log.error("session recording failed order=%s error=%s", order_id, type(error).__name__)
        receipt(None)
        return outcome.model_copy(update={"usage": measured})

    def _lease(
        self,
        order_id: UUID | None,
        worker: WorkerId | None,
        lease_generation: int | None,
        repo: str | None,
    ) -> UUID | None:
        if recording_order_id(order_id, lease_generation) != order_id:
            raise ValidationError("session task must name its scheduled run order")
        if order_id is None:
            if worker is not None:
                raise ValidationError("manual sessions do not have a worker lease")
            return None
        if not worker or lease_generation is None:
            raise ValidationError("ordered sessions require the original worker and generation")
        order = leased_session_order(
            self._services, self._clock, order_id, worker, lease_generation
        )
        if order.repository_id is None or not repo:
            raise ValidationError("ordered review requires its repository")
        expected = self._services.portfolio.get_repository(order.repository_id).url
        if HttpsRepoUrl.parse(repo, self._hosts) != HttpsRepoUrl.parse(expected, self._hosts):
            raise ValidationError("session repository differs from the leased order")
        return order.repository_id
