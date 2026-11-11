from __future__ import annotations

import logging
import os
import stat
from collections.abc import Callable, Mapping, Sequence
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
    SessionFile,
    SessionOutput,
    SessionRecord,
    SessionResult,
    SessionTask,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import SourceType

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
    root: Path,
    doc: ArtifactDocument,
    source: Provenance | None,
    order_id: UUID | None,
) -> UUID:
    index = PacketIndex.model_validate_json(read_file(root, "input/below-range.json"))
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
    record: Callable[[Services, Path, ArtifactDocument, Provenance | None, UUID | None], UUID]
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
    ) -> SessionTask:
        doors = SESSIONS.get((skill, mode))
        if doors is None:
            raise ValidationError("session mode is not registered")
        if self._osv_access == "air-gapped":
            raise ValidationError("below-range requires OSV API access")
        self._lease(order_id, worker, repo)
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
            skill=skill,
            mode=mode,
            executor_session=None,
            models=models,
            task_sha256=digest(task.payload),
            inputs=files,
            output=SessionOutput(path=doors.output, sha256=None, artifact_id=None),
        )
        (root / AUDIT).write_text(audit.model_dump_json())
        log.info(
            "session staged skill=%s mode=%s files=%d bytes=%d order=%s",
            skill,
            mode,
            len(files),
            sum(f.bytes for f in files),
            order_id,
        )
        return task

    def task(self, root: Path) -> tuple[SessionTask, SessionRecord]:
        task = SessionTask.parse(read_file(root, "task.json"))
        audit = SessionRecord.model_validate_json(read_file(root, AUDIT))
        doors = SESSIONS.get((task.skill, task.mode))
        if (
            doors is None
            or task.output.path != doors.output
            or task.output.schema != doors.document.schema
        ):
            raise ValidationError("task does not match its registered session mode")
        if (
            digest(task.payload) != audit.task_sha256
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
        self._lease(order_id, worker, task.args[0] if task.args else None)
        measured = usage(result) if result else ()
        output_digest, artifact_id = None, None
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
                artifact_id = doors.record(self._services, root, doc, source, order_id)
                outcome = JobResult.succeeded(written=(str(artifact_id),))
        except (OSError, ValidationError) as error:
            if not failed:
                log.warning(
                    "session output refused order=%s error=%s", order_id, type(error).__name__
                )
                outcome = JobResult.failed(OrderReason.SESSION_OUTPUT_INVALID)
        except TraustError as error:
            log.error("session recording failed order=%s error=%s", order_id, type(error).__name__)
        recorded = SessionRecord(
            **{
                **audit.model_dump(),
                "executor_session": result.session if result else None,
                "output": SessionOutput(
                    path=task.output.path, sha256=output_digest, artifact_id=artifact_id
                ),
            }
        )
        if order_id is not None:
            self._services.ops.record_session(order_id, worker, recorded)
        else:
            print(recorded.model_dump_json())
        return outcome.model_copy(update={"usage": measured})

    def _lease(self, order_id: UUID | None, worker: WorkerId | None, repo: str | None) -> None:
        if order_id is None:
            if worker is not None:
                raise ValidationError("manual sessions do not have a worker lease")
            return
        if not worker:
            raise ValidationError("ordered sessions require the claiming worker")
        order = self._services.ops.get(order_id)
        if (
            order.state != OrderState.LEASED
            or order.lease_holder != worker
            or order.lease_expires_at is None
            or order.lease_expires_at <= self._clock.now()
        ):
            raise ConflictError("session order is not leased to this worker")
        if order.repository_id is None or not repo:
            raise ValidationError("ordered review requires its repository")
        expected = self._services.portfolio.get_repository(order.repository_id).url
        if HttpsRepoUrl.parse(repo, self._hosts) != HttpsRepoUrl.parse(expected, self._hosts):
            raise ValidationError("session repository differs from the leased order")
