"""What every ``traust <group> <op>`` door on traust-core shares: its parser and how it answers."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError as ModelValidationError
from traust_core.v1.errors import NotFoundError, TraustError, ValidationError
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.inventory import Product, RefName, RepositoryRef
from traust_core.v1.models.operations import JobResult, Outcome, RecordKind, RunOrder
from traust_core.v1.models.values import GitSha, ProductSlug
from traust_core.v1.models.vocabulary import Ecosystem, RefKind, SourceType

from traust.context import Context, add_config_home_arg, load_recorder


def parser(group: str, op: str, about: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=f"traust {group} {op}", description=about)
    add_config_home_arg(ap)
    return ap


def add_branch_arg(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--branch",
        help="the branch the commit was scanned on; named like the forge-observed default "
        "branch, the record is on the default line. Without it the commit is recorded bare "
        "(never guessed from the sha), on the default line only at the observed default head",
    )


# `traust session run` sets this for the agent it starts, so a record door the skill calls
# binds what it records to the order that ran it.
RUN_ORDER_ENV = "TRAUST_RUN_ID"
ORDER_STARTED_ENV = "TRAUST_ORDER_STARTED_AT"


def add_run_order_arg(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--run-id",
        type=uuid.UUID,
        default=os.environ.get(RUN_ORDER_ENV) or None,
        help=f"the leased order this records for (default: ${RUN_ORDER_ENV}, set by session run)",
    )


def add_order_started_arg(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--order-started-at",
        default=os.environ.get(ORDER_STARTED_ENV),
        help=f"start of the original claim (default: ${ORDER_STARTED_ENV})",
    )


def order_started_at(raw: str | None = None) -> datetime:
    inherited = os.environ.get(ORDER_STARTED_ENV)
    if inherited is not None:
        if raw not in (None, inherited):
            raise ValidationError("--order-started-at conflicts with the original claim")
        raw = inherited
    try:
        at = datetime.fromisoformat(raw) if raw else None
    except ValueError:
        at = None
    if at is None or at.tzinfo is None:
        raise ValidationError("a bound record requires the original claim's zoned start time")
    return at


def recording_order_id(explicit: uuid.UUID | None) -> uuid.UUID | None:
    """A scheduled writer may not drop or replace the order inherited from the runner."""
    if RUN_ORDER_ENV not in os.environ:
        if explicit is None and ORDER_STARTED_ENV in os.environ:
            raise ValidationError("claim timestamp without a scheduled run order id")
        return explicit
    try:
        inherited = uuid.UUID(os.environ[RUN_ORDER_ENV])
    except ValueError as error:
        raise ValidationError("invalid scheduled run order id") from error
    if explicit not in (None, inherited):
        raise ValidationError("--run-id conflicts with the scheduled run order")
    return inherited


def report_provenance(
    order_id: uuid.UUID | None, source: SourceType, order_started: str | None = None
) -> Provenance:
    order_id = recording_order_id(order_id)
    return Provenance(
        run_id=order_id or uuid.uuid4(),
        source=source,
        occurred_at=order_started_at(order_started) if order_id is not None else datetime.now(UTC),
    )


def scoped_recording_order(
    core: Context, order_id: uuid.UUID, kind: RecordKind, source: SourceType
) -> RunOrder:
    """Preflight a session before launching it; its writer rechecks under the lease lock."""
    services = core.services()
    order = services.ops.get(order_id)
    if order.repository_id is None or order.started_at is None:
        raise ValidationError("recording needs a leased repository order")
    origin = report_provenance(order_id, source)
    order = services.ops.check_recording(
        order_id,
        load_recorder(core),
        kind,
        order.repository_id,
        origin,
    )
    if origin.occurred_at != order.started_at:
        raise ValidationError("recording belongs to a different lease attempt")
    services.findings.decisions.require_order_ledger(signed=kind is RecordKind.TRIAGE)
    return order


def register_commit(
    services: Any, repository_id: uuid.UUID, sha: str, branch: str | None
) -> RepositoryRef:
    """The scanned commit's ref: on its branch when the caller names one, else bare. Core
    decides the default line from the forge-observed default branch name."""
    name, kind = (RefName(branch), RefKind.BRANCH) if branch else (None, None)
    return services.portfolio.register_ref(repository_id, GitSha.parse(sha), name, kind)


def interactive() -> Provenance:
    """The provenance of a document a person hands in at the command line, now."""
    return Provenance(
        run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=datetime.now(UTC)
    )


def when(raw: str | None) -> datetime | None:
    """An ``--as-of`` style time; it must carry a zone."""
    if raw is None:
        return None
    at = datetime.fromisoformat(raw)
    if at.tzinfo is None:
        raise ValidationError(f"{raw}: give a time zone (e.g. 2026-10-23T09:00:00Z)")
    return at


def products(services: Any, slugs: list[str]) -> list[Product]:
    """Each slug's registered product, once each, in order."""
    found = []
    for slug in dict.fromkeys(slugs):
        product = services.portfolio.find_product(ProductSlug(slug))
        if product is None:
            raise NotFoundError(f"product {slug} is not registered (`traust products list`)")
        found.append(product)
    return found


def run(call: Callable[[], object], *, redact: bool = False) -> int:
    """Print the result; optionally keep submitted content out of refusal messages."""
    try:
        out = call()
    except (OSError, TraustError, ModelValidationError) as e:
        detail = type(e).__name__ if redact else str(e)
        print(f"ERROR: {detail}", file=sys.stderr)
        return 2
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=2, default=str))
    return 0


EXIT_CODES = {Outcome.SUCCEEDED: 0, Outcome.FAILED: 1, Outcome.DEGRADED: 4, Outcome.REFUSED: 5}


def answer(result: JobResult) -> int:
    """A materializer's door: print the JobResult; the exit code is its outcome."""
    print(result.model_dump_json())
    return EXIT_CODES[result.outcome]


def package_id(services: Any, ecosystem: str, name: str) -> uuid.UUID:
    """The recorded package's id by ecosystem and name (Exposure's ``find_package``)."""
    found = services.exposure.find_package(Ecosystem(ecosystem), name)
    if found is None:
        raise NotFoundError(f"no {ecosystem} package named {name} is recorded")
    return found.id
