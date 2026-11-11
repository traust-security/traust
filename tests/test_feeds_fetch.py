"""`traust feeds fetch`: the feeds_cache materializer end to end on traust-core, SQLite, with the
feed hosts replayed from tests/fixtures/feeds."""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.errors import ServiceError
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.models.operations import JobResult, OrderReason, OrderState, RunOrder
from traust_core.v1.providers.http import HttpFetcher
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from traust.cli import feeds_fetch
from traust.context import load

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
FEEDS = ("epss", "kev", "rh-cve", "vex")
HOSTS = {
    "https://epss.cyentia.com/": gzip.compress(
        (FIXTURES / "epss_scores-current.csv").read_bytes(), mtime=0
    ),
    "https://www.cisa.gov/": (FIXTURES / "known_exploited_vulnerabilities.json").read_bytes(),
    "https://access.redhat.com/hydra/": (FIXTURES / "rh_cve_page.json").read_bytes(),
    "https://access.redhat.com/security/data/csaf/v2/vex/": (FIXTURES / "changes.csv").read_bytes(),
}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "config-home"
    shutil.copytree(os.environ["TRAUST_CONFIG_HOME"], home)
    (home / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    return home


@pytest.fixture
def hosts(monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes | Exception]:
    """Replies by URL prefix; tests swap one for an error. Every URL asked for is recorded."""
    replies: dict[str, bytes | Exception] = dict(HOSTS)
    asked: list[str] = []

    def get(self: HttpFetcher, url: str) -> bytes:
        asked.append(url)
        reply = next(r for prefix, r in replies.items() if url.startswith(prefix))
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(HttpFetcher, "get", get)
    replies["asked"] = asked  # type: ignore[assignment]
    return replies


def fetch(home: Path, *argv: str) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = feeds_fetch.main(["--config-home", str(home), *argv])
    return rc, json.loads(out.getvalue())


def payload(home: Path, feed: str) -> bytes | None:
    core = load(home)
    core.register_feeds()
    return core.services().exposure.feed_payload(FeedName(feed))


def test_every_security_feed_is_snapshotted(home: Path, hosts: dict) -> None:
    assert fetch(home) == (0, JobResult.succeeded().model_dump(mode="json"))
    assert payload(home, "vex") == HOSTS["https://access.redhat.com/security/data/csaf/v2/vex/"]
    cves = [r["CVE"] for r in json.loads(payload(home, "rh-cve") or b"[]")]
    assert cves == sorted(r["CVE"] for r in json.loads(HOSTS["https://access.redhat.com/hydra/"]))
    assert all(
        set(r) <= {"CVE", "public_date", "bugzilla_description", "severity", "cvss3_score", "CWE"}
        for r in json.loads(payload(home, "rh-cve") or b"[]")
    )


def test_the_next_run_asks_red_hat_only_for_what_published_since(home: Path, hosts: dict) -> None:
    fetch(home, "--feed", "rh-cve")
    hosts["asked"].clear()
    fetch(home, "--feed", "rh-cve")
    assert hosts["asked"] == [
        "https://access.redhat.com/hydra/rest/securitydata/cve.json"
        "?page=1&per_page=1000&after=2026-10-22"
    ]


def test_one_feed_by_name(home: Path, hosts: dict) -> None:
    assert fetch(home, "--feed", "kev")[0] == 0
    assert payload(home, "kev") is not None and payload(home, "epss") is None


def test_a_source_that_fails_after_a_good_run_degrades_and_keeps_its_snapshot(
    home: Path, hosts: dict, caplog: pytest.LogCaptureFixture
) -> None:
    fetch(home)
    kept = payload(home, "kev")
    hosts["https://www.cisa.gov/"] = ServiceError("https://www.cisa.gov/...: HTTP 503")
    rc, result = fetch(home)
    assert (rc, result["outcome"], result["degraded"]) == (4, "degraded", {"kev": 1})
    assert result["reason"] == OrderReason.SOURCE_UNAVAILABLE
    assert "kev: https://www.cisa.gov/...: HTTP 503" in caplog.text
    assert payload(home, "kev") == kept


def test_a_source_with_no_snapshot_at_all_fails_the_run(home: Path, hosts: dict) -> None:
    hosts["https://epss.cyentia.com/"] = b"not a gzip payload"
    rc, result = fetch(home)
    assert (rc, result["outcome"]) == (1, "failed")
    assert result["reason"] == OrderReason.SNAPSHOT_UNAVAILABLE
    assert payload(home, "kev") is not None


def test_an_unknown_feed_is_a_bad_request(home: Path, hosts: dict) -> None:
    rc, result = fetch(home, "--feed", "nvd")
    assert (rc, result["outcome"]) == (1, "failed")
    assert result["reason"] == OrderReason.BAD_REQUEST


def test_a_run_for_an_order_links_its_snapshots_to_it(home: Path, hosts: dict) -> None:
    core = load(home)
    with SqlTraustUnitOfWork(core.database) as uow:
        order = uow.run_orders.add(
            RunOrder(asset="feeds_cache", state=OrderState.QUEUED, priority=10, requested_by="t")
        )
        uow.commit()
    assert fetch(home, "--feed", "kev", "--run-id", str(order.id))[0] == 0
    with SqlTraustUnitOfWork(core.database) as uow:
        snapshot = uow.feed_snapshots.latest("kev")
    assert snapshot is not None and snapshot.run_order_id == order.id


@pytest.mark.parametrize("run_id", ["not-a-uuid", "order-7"])
def test_a_run_id_that_is_not_an_order_is_a_bad_request(
    home: Path, hosts: dict, run_id: str
) -> None:
    rc, result = fetch(home, "--run-id", run_id)
    assert (rc, result["outcome"]) == (1, "failed")
    assert hosts["asked"] == []


def test_the_product_registry_is_pointed_at_its_own_command(home: Path, hosts: dict) -> None:
    with pytest.raises(SystemExit) as exit_:
        feeds_fetch.main(["--config-home", str(home), "--feed", "product-definitions"])
    assert exit_.value.code == 2 and hosts["asked"] == []
