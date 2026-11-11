"""Harness policy for deriving an event's `occurred_at` from a report."""

from __future__ import annotations

import argparse

from traust_core.v1.models.values import TimestampError, to_rfc3339


def _stated(value: object) -> bool:
    if value is None:
        return False
    return bool(value.strip()) if isinstance(value, str) else True


def report_occurred_at(
    report_date: object,
    recorded_at: object,
    *,
    field: str = "metadata.date",
) -> str:
    """RFC 3339 `occurred_at` from a report date, falling back to `recorded_at`.

    A report that states no date has no determination time beyond when the
    event was appended. A report that states an unusable one violates its own
    schema, so it raises instead of getting a silent substitute.
    """
    if not _stated(report_date):
        return to_rfc3339(recorded_at)
    try:
        return to_rfc3339(report_date)
    except TimestampError as exc:
        raise TimestampError(f"{field}: {exc}") from None


def recorded_at_arg(value: str) -> str:
    """argparse ``type`` for ``--recorded-at``.

    Every producer accepts this flag and feeds it straight to `recorded_at`,
    whose `[:10]` prefix reaches interactive `source.ref` and therefore
    `event_id`. Validating at the CLI boundary fails before an event is built,
    rather than at submit time or not at all.
    """
    try:
        return to_rfc3339(value)
    except TimestampError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


__all__ = ["recorded_at_arg", "report_occurred_at"]
