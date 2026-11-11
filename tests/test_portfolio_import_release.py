"""`traust portfolio import-release`: the CLI layer only. A payload's commit URLs become one
`PortfolioService.import_release` call for the product version; the answer is the release as
JSON; a typed error is exit 2 with its reason. Idempotency and the all-or-nothing write are
traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConflictError, NotFoundError
from traust_core.v1.models.inventory import Release, ReleaseCommit
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from traust.cli import portfolio_onboard

PRODUCT = SimpleNamespace(id=uuid.uuid4(), slug="openshift")
RELEASE = Release(id=uuid.uuid4(), product_id=PRODUCT.id, version="4.21.3")
SHA, OTHER = "a" * 40, "b" * 40
ETCD = HttpsRepoUrl("github.com", "example-org/cluster-etcd-operator")
OC = HttpsRepoUrl("gitlab.com", "example-org/oc")
PAYLOAD = (
    f"cluster-etcd-operator https://github.com/example-org/cluster-etcd-operator/commit/{SHA}\n"
    "\n"
    f"cli https://gitlab.com/example-org/oc/-/commit/{OTHER}\n"
    f"cli-artifacts https://gitlab.com/example-org/oc/-/commit/{OTHER}/\n"
)


class Door:
    """Records each call; answers with `result`, or raises it when it is an exception."""

    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def import_release(monkeypatch: pytest.MonkeyPatch) -> Door:
    door = Door(RELEASE)
    portfolio = SimpleNamespace(
        find_product=lambda slug: {"openshift": PRODUCT}.get(str(slug)), import_release=door
    )
    monkeypatch.setattr(Context, "services", lambda self: SimpleNamespace(portfolio=portfolio))
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, payload: str, *argv: str) -> tuple[int, Any]:
    commits = home.parent / "payload-image-repo-map.txt"
    commits.write_text(payload)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        release = ("--product", "openshift", "--version", "4.21.3", "--commits", str(commits))
        rc = portfolio_onboard.import_release(["--config-home", str(home), *release, *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_each_commit_url_is_one_commit_of_one_import(import_release: Door, home: Path) -> None:
    rc, out = run(home, PAYLOAD, "--branch", "release-4.21")

    assert rc == 0
    assert out == RELEASE.model_dump(mode="json")
    branch = "release-4.21"
    assert import_release.calls == [
        (
            PRODUCT.id,
            "4.21.3",
            [
                ReleaseCommit(url=ETCD, sha=GitSha(SHA), branch=branch),
                ReleaseCommit(url=OC, sha=GitSha(OTHER), branch=branch),
                ReleaseCommit(url=OC, sha=GitSha(OTHER), branch=branch),
            ],
        )
    ]


def test_without_a_branch_the_commits_are_bare(import_release: Door, home: Path) -> None:
    assert run(home, PAYLOAD)[0] == 0
    [(_, _, commits)] = import_release.calls
    assert {c.branch for c in commits} == {None}


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ("cli https://github.com/example-org/oc\n", "payload-image-repo-map.txt:1: not a commit"),
        (f"cli https://github.com/example-org/oc/commit/{SHA[:12]}\n", "not a commit URL"),
        (f"cli https://evil.example/org/oc/commit/{SHA}\n", "evil.example"),
    ],
)
def test_a_line_that_is_not_a_commit_is_exit_2_and_imports_nothing(
    import_release: Door, home: Path, payload: str, reason: str
) -> None:
    rc, err = run(home, payload)

    assert rc == 2 and reason in err
    assert import_release.calls == []


def test_an_unregistered_product_is_exit_2(import_release: Door, home: Path) -> None:
    rc, err = run(home, PAYLOAD, "--product", "nope")

    assert rc == 2 and "product nope is not registered" in err
    assert import_release.calls == []


@pytest.mark.parametrize(
    "refusal",
    [
        NotFoundError("release 4.21.3: unregistered repositories ['https://github.com/x/y']"),
        ConflictError("release 4.21.3 of product p already ships 2 commits"),
    ],
)
def test_a_door_refusal_is_exit_2_with_its_reason(
    import_release: Door, home: Path, refusal: Exception
) -> None:
    import_release.result = refusal

    rc, err = run(home, PAYLOAD)

    assert rc == 2 and str(refusal) in err
