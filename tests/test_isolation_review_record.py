"""isolation-review: one review recorded on each commit of the service's repo set, on traust-core
in-process (SQLite, and Postgres when TRAUST_TEST_DATABASE_URL is set)."""

from __future__ import annotations

import json
from pathlib import Path

from tests.test_assessment_record import core_home, run
from tests.test_isolation_review import _valid_report

__all__ = ["core_home"]

REPOS = [
    ("https://github.com/example/api-server", "a" * 40),
    ("https://github.com/example/worker", "b" * 40),
]


def test_one_review_is_an_assessment_of_each_commit_it_covers(core_home: Path, tmp_path: Path):
    review = tmp_path / "example-service-isolation-review.json"
    review.write_text(json.dumps(_valid_report()))

    def record(url: str, sha: str) -> str:
        rc, out = run(
            core_home, str(review), "--kind", "isolation_review", "--repo-url", url, "--sha", sha
        )
        assert rc == 0, out
        return out["id"]

    first = [record(url, sha) for url, sha in REPOS]
    again = [record(url, sha) for url, sha in REPOS]

    assert len(set(first)) == 2
    assert again == first  # the same review (same reviewed_at) on the same commit is one run


def test_a_review_failing_its_schema_records_nothing(core_home: Path, tmp_path: Path):
    doc = _valid_report()
    del doc["posture"]
    review = tmp_path / "bad-isolation-review.json"
    review.write_text(json.dumps(doc))
    url, sha = REPOS[0]

    rc, err = run(
        core_home, str(review), "--kind", "isolation_review", "--repo-url", url, "--sha", sha
    )

    assert rc == 2
    assert "posture" in err


def test_a_gap_naming_no_listed_interface_records_nothing(core_home: Path, tmp_path: Path):
    doc = _valid_report()
    doc["gaps"][0]["interface_id"] = "IF-99"
    review = tmp_path / "bad-isolation-review.json"
    review.write_text(json.dumps(doc))
    url, sha = REPOS[0]

    rc, err = run(
        core_home, str(review), "--kind", "isolation_review", "--repo-url", url, "--sha", sha
    )

    assert rc == 2
    assert "IF-99" in err
