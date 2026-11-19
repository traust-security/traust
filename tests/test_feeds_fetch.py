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
from traust_core.v1.models.dependencies import Advisory, AdvisoryMatch, FeedName
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.operations import (
    DegradedKey,
    JobResult,
    OrderReason,
    OrderState,
    RunOrder,
)
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

    def get(self: HttpFetcher, url: str, *args: object, **kw: object) -> bytes:
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


# The per-advisory document hosts, matched before the whole-file feeds' broader prefixes.
DOCUMENT_HOSTS = {
    "https://cveawg.mitre.org/api/cve/": b'{"cveMetadata": {"state": "PUBLISHED"}}',
    "https://services.nvd.nist.gov/": b'{"vulnerabilities": []}',
    "https://api.osv.dev/v1/vulns/": b'{"id": "GHSA-jfh8-c2jp-5v3q"}',
    "https://access.redhat.com/hydra/rest/securitydata/cve/": b'{"name": "CVE-2021-44228"}',
}


def link_advisory(home: Path) -> None:
    """A finding whose advisory core kept GHSA-first, its CVE only an alias."""
    core = load(home)
    with SqlTraustUnitOfWork(core.database) as uow:
        ghsa = uow.advisories.add(Advisory(identifier="GHSA-jfh8-c2jp-5v3q"))
        uow.advisories.add(Advisory(identifier="CVE-2021-44228", alias_of_id=ghsa.id))
        repo = uow.repositories.add(Repository(url="https://github.com/example/app", public=True))
        assert repo.id is not None
        uow.findings.add(
            Finding(
                repository_id=repo.id,
                fingerprint_algo="v3",
                fingerprint="fp-1",
                title="log4j-core vulnerable",
                advisory_id=ghsa.id,
                advisory_match=AdvisoryMatch.CONFIRMED,
            )
        )
        uow.commit()


@pytest.fixture
def documents(hosts: dict) -> dict:
    replies = {**DOCUMENT_HOSTS, **hosts}  # the documents' prefixes first
    hosts.clear()
    hosts.update(replies)
    return hosts


def assert_registered(home: Path, result: dict[str, Any]) -> None:
    """Every degraded key passes core's completion rule (the contracts' degraded-key vocabulary,
    or a registered feed), so the engine records the run instead of refusing its completion."""
    core = load(home)
    core.register_feeds()
    allowed = {*core.feeds.names(), *(k.value for k in DegradedKey)}
    assert set(result["degraded"]) <= allowed, set(result["degraded"]) - allowed


def stored(home: Path, source: str, identifier: str) -> bytes | None:
    core = load(home)
    core.register_feeds()
    doc = core.services().exposure.stored_document(source, identifier)
    return None if doc is None else doc.data


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


def test_an_unset_feed_key_variable_is_a_refusal_not_a_traceback(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("TEST_NVD_KEY", raising=False)
    document = yaml.safe_load((home / "traust.yaml").read_text())
    document["feeds"] = {"api_keys": {"nvd": "TEST_NVD_KEY"}}
    (home / "traust.yaml").write_text(yaml.safe_dump(document))
    assert feeds_fetch.main(["--config-home", str(home)]) == 2
    assert "feeds.api_keys.nvd names unset variable TEST_NVD_KEY" in capsys.readouterr().err


def test_a_full_run_also_keeps_every_linked_advisorys_documents(
    home: Path, documents: dict
) -> None:
    link_advisory(home)
    assert fetch(home) == (0, JobResult.succeeded().model_dump(mode="json"))
    cve, ghsa = "CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"
    assert stored(home, "cve-list", cve) == DOCUMENT_HOSTS["https://cveawg.mitre.org/api/cve/"]
    assert stored(home, "nvd", cve) == DOCUMENT_HOSTS["https://services.nvd.nist.gov/"]
    assert stored(home, "ghsa", ghsa) == DOCUMENT_HOSTS["https://api.osv.dev/v1/vulns/"]
    assert stored(home, "rh-cve", cve) is not None
    assert stored(home, "nvd", ghsa) is None  # the canonical GHSA id never reaches a CVE source


def test_the_documents_partition_refreshes_only_the_documents(home: Path, documents: dict) -> None:
    link_advisory(home)
    assert fetch(home, "--feed", "advisory-documents")[0] == 0
    assert payload(home, "kev") is None and payload(home, "epss") is None
    assert stored(home, "nvd", "CVE-2021-44228") is not None


def test_one_feed_by_name_leaves_the_documents_alone(home: Path, documents: dict) -> None:
    link_advisory(home)
    fetch(home, "--feed", "kev")
    assert not any("nvd.nist.gov" in url for url in documents["asked"])


def test_a_document_source_that_fails_degrades_the_run_and_the_feeds_still_snapshot(
    home: Path, documents: dict, caplog: pytest.LogCaptureFixture
) -> None:
    link_advisory(home)
    documents["https://services.nvd.nist.gov/"] = ServiceError("HTTP 503")
    rc, result = fetch(home)
    assert (rc, result["outcome"], result["degraded"]) == (4, "degraded", {"error": 1})
    assert_registered(home, result)
    assert result["reason"] == OrderReason.SOURCE_UNAVAILABLE
    assert payload(home, "kev") is not None and "nvd documents" in caplog.text


def test_when_every_document_source_fails_the_run_is_degraded_not_failed(
    home: Path, documents: dict
) -> None:
    link_advisory(home)
    for prefix in DOCUMENT_HOSTS:
        documents[prefix] = ServiceError("HTTP 503")
    rc, result = fetch(home)
    assert (rc, result["outcome"], result["degraded"]) == (4, "degraded", {"error": 1})
    assert_registered(home, result)
    assert payload(home, "epss") is not None


def test_with_no_linked_advisory_no_document_is_asked_for(home: Path, documents: dict) -> None:
    assert fetch(home)[0] == 0
    assert not any(url.startswith(tuple(DOCUMENT_HOSTS)) for url in documents["asked"])


def test_a_feed_with_no_snapshot_fails_the_run_but_the_documents_still_refresh(
    home: Path, documents: dict
) -> None:
    link_advisory(home)
    documents["https://epss.cyentia.com/"] = b"not a gzip payload"
    rc, result = fetch(home)
    assert (rc, result["outcome"], result["reason"]) == (
        1,
        "failed",
        OrderReason.SNAPSHOT_UNAVAILABLE,
    )
    assert stored(home, "nvd", "CVE-2021-44228") is not None


def test_a_failed_run_still_names_the_document_sources_that_failed(
    home: Path, documents: dict
) -> None:
    link_advisory(home)
    documents["https://epss.cyentia.com/"] = b"not a gzip payload"
    documents["https://services.nvd.nist.gov/"] = ServiceError("HTTP 503")
    rc, result = fetch(home)
    assert (rc, result["outcome"]) == (1, "failed")
    assert result["degraded"] == {"epss": 1, "error": 1}
    assert_registered(home, result)


def test_a_store_failure_reading_the_names_degrades_the_run_and_the_feeds_still_count(
    home: Path, documents: dict, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Never a crash: the whole-file feeds already snapshotted, so the order is degraded."""
    from traust_core.v1.errors import RepositoryError
    from traust_core.v1.services.exposure import ExposureService

    link_advisory(home)

    def unreadable(self: ExposureService, run_order_id: object = None) -> object:
        try:
            raise TimeoutError("socket closed")
        except TimeoutError as cause:
            raise RepositoryError(
                "the store is unreachable", operation="linked advisories"
            ) from cause

    monkeypatch.setattr(ExposureService, "refresh_advisory_documents", unreadable)
    rc, result = fetch(home)
    assert (rc, result["outcome"], result["degraded"]) == (4, "degraded", {"error": 1})
    assert_registered(home, result)
    assert payload(home, "kev") is not None
    assert (
        "advisory documents error_type=RepositoryError operation=linked advisories "
        "cause=TimeoutError: the store is unreachable"
    ) in caplog.text
