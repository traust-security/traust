"""Harness policy for `occurred_at`. The transform itself is tested in contracts."""

from __future__ import annotations

import argparse

import pytest
from traust_core.v1.models.values import TimestampError

from traust.lib.event_time import recorded_at_arg, report_occurred_at

RECORDED = "2026-07-11T12:00:00+00:00"


@pytest.mark.parametrize(
    ("report_date", "expected"),
    [
        ("2026-07-09", "2026-07-09T00:00:00+00:00"),
        ("2026-07-09T14:30:00Z", "2026-07-09T14:30:00Z"),
        ("2026-07-09T14:30:00+02:00", "2026-07-09T14:30:00+02:00"),
    ],
)
def test_uses_the_report_date_when_usable(report_date: str, expected: str) -> None:
    assert report_occurred_at(report_date, RECORDED) == expected


@pytest.mark.parametrize("report_date", [None, "", "   "])
def test_falls_back_when_no_date_is_stated(report_date: object) -> None:
    assert report_occurred_at(report_date, RECORDED) == RECORDED


@pytest.mark.parametrize(
    "report_date",
    [
        True,  # "triage_completed": true — the original root cause
        False,
        "TrueT00:00:00+00:00",
        "2026-01-16T00:00:00ZT00:00:00+00:00",
        "banana",
        20260709,
        "2026-07-09T14:30:00",  # naive, no offset
    ],
)
def test_unusable_stated_date_raises(report_date: object) -> None:
    with pytest.raises(TimestampError):
        report_occurred_at(report_date, RECORDED)


def test_error_names_the_offending_field() -> None:
    with pytest.raises(TimestampError, match="triage_completed"):
        report_occurred_at(True, RECORDED, field="triage_completed")


def test_bad_recorded_at_also_raises() -> None:
    with pytest.raises(TimestampError):
        report_occurred_at(None, "not-a-timestamp")


class TestRecordedAtArg:
    """--recorded-at is accepted by six producers and feeds event_id."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (RECORDED, RECORDED),
            ("2026-07-11T12:00:00Z", "2026-07-11T12:00:00Z"),
            ("2026-07-11", "2026-07-11T00:00:00+00:00"),
        ],
    )
    def test_accepts_and_normalizes(self, value: str, expected: str) -> None:
        assert recorded_at_arg(value) == expected

    def test_conversion_preserves_the_event_id_day_key(self) -> None:
        assert recorded_at_arg("2026-07-11")[:10] == "2026-07-11"

    @pytest.mark.parametrize(
        "value",
        ["banana", "", "TrueT00:00:00+00:00", "2026-07-11T12:00:00", "2026-13-45T00:00:00+00:00"],
    )
    def test_rejects_as_an_argparse_error(self, value: str) -> None:
        with pytest.raises(argparse.ArgumentTypeError):
            recorded_at_arg(value)
