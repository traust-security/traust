"""`session run --checkout`: the order's commit — the head its repo_state observation recorded,
not the branch's current tip — through the checkout service, with the history a diff scan
anchors at, released when the session ends. A local repository stands in for the forge (the
https URL resolves to it through git's insteadOf in an isolated HOME, which core's git keeps)."""

from __future__ import annotations

import shlex
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.identity import IdentitySource, Principal
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import OrderRequest, WorkerId
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.process import ProcessRunner
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_core.v1.services.repo_checkout import RepoCheckoutService

from tests.test_repo_checkout import REPO, Forge, forge
from traust.cli import session
from traust.context import load
from traust.paths import HARNESS_ROOT

__all__ = ["forge"]

pytestmark = pytest.mark.requires_git


def _git(*argv: str) -> str:
    done = subprocess.run(["git", *argv], capture_output=True, text=True, check=True)
    return done.stdout.strip()


def _observed_head(forge: Forge, sha: str) -> None:
    """Register the repository with `sha` as its observed default head (a repo_state
    assessment on the default line), the commit an order for it names."""
    core = load(forge.config)
    services = core.services()
    repo = services.portfolio.register_repository(
        HttpsRepoUrl.parse(REPO, core.config.forge_hosts), False
    )
    assert repo.id is not None
    with SqlTraustUnitOfWork(core.database) as uow:
        head = uow.repository_refs.add(
            RepositoryRef(
                repository_id=repo.id, name="main", kind="branch", is_default=True, sha=sha
            )
        )
        assert head.id is not None
        uow.assessments.add(
            Assessment(
                repository_ref_id=head.id,
                kind=AssessmentKind.REPO_STATE,
                status="completed",
                assessor="test",
                assessor_version="1",
                occurred_at=datetime.now(UTC),
            )
        )
        uow.commit()


def test_the_workspace_is_the_orders_commit_with_history_released_afterwards(
    forge: Forge,
) -> None:
    _observed_head(forge, forge.head)
    moved = forge.move()  # the branch moved on: the session still gets the order's commit
    with session.checkout(REPO, forge.config) as workspace:
        git = GitCheckout(ProcessRunner(["git"]))
        head = _git("-C", str(workspace.path), "rev-parse", "HEAD")
        assert head == forge.head and head != moved
        # what `assessments prepare --diff` refuses without: the anchor and its numstat
        assert git.reachable(workspace.path, forge.anchor)
        assert [r.path for r in git.numstat(workspace.path, forge.anchor)] == ["changed.py"]
        assert not workspace.path.is_relative_to(HARNESS_ROOT)
    assert not workspace.path.exists()  # released when the session ends


def test_scheduled_triage_receives_the_assessed_tree_not_the_newer_head(
    forge: Forge, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _observed_head(forge, forge.head)
    moved = forge.move()
    core = load(forge.config)
    services = core.services()
    repo = services.portfolio.find_repository(HttpsRepoUrl.parse(REPO, core.config.forge_hosts))
    caller = Principal(
        identity="checkout-test",
        kind=ActorKind.MACHINE,
        display="Test",
        verified_by=IdentitySource.OIDC,
    )
    submitted = services.ops.submit(
        OrderRequest(asset="checkout_fixture", priority=1, repository_id=repo.id),
        Principal(
            identity="checkout-operator",
            kind=ActorKind.HUMAN,
            display="Operator",
            verified_by=IdentitySource.OIDC,
        ),
    )
    services.ops.admit(submitted.id)  # submit plans; the engine's admission queues it
    order = services.ops.claim(WorkerId(caller.ref), timedelta(minutes=5), order_id=submitted.id)
    assert order is not None
    source = uuid4()
    monkeypatch.setattr(session, "load_recorder", lambda _: caller)
    monkeypatch.setattr(session, "resolve_model", lambda _: "fixture-model")
    monkeypatch.setattr(session, "order_assessments", lambda *_: [])
    monkeypatch.setattr(
        session,
        "_triage_source",
        lambda *_: (source, GitSha.parse(forge.anchor), ()),
    )
    seen = []

    def agent(command, skill, env):
        words = shlex.split(command[-1])
        assert words[:3] == ["/triage", str(source), "--repo"]
        assert words[-2:] == ["--lease-generation", str(order.lease_generation)]
        assert env["TRAUST_RUN_ID"] == str(order.id)
        target = Path(words[3])
        assert not target.is_relative_to(HARNESS_ROOT)
        assert (target / "audited.py").read_text() == "x = 1\n"
        assert not (target / "changed.py").exists()
        assert _git("-C", str(target), "rev-parse", "HEAD") == forge.anchor != moved
        seen.append(target)
        return subprocess.CompletedProcess(command, 0), ()

    monkeypatch.setattr(session, "session", agent)
    rc = session.run(
        [
            "--config-home",
            str(forge.config),
            "--skill",
            "triage",
            "--role",
            "triage-verifier",
            "--repo",
            REPO,
            "--run-id",
            str(order.id),
            "--lease-generation",
            str(order.lease_generation),
        ]
    )
    # Reading the source is not itself proof of a recording.
    assert rc == 1 and '"reason":"session-output-invalid"' in capsys.readouterr().out
    assert len(seen) == 1 and not seen[0].exists()


def test_a_failed_release_is_reported_alongside_not_instead_of_the_session(
    forge: Forge, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The session's outcome stands: a release that fails at teardown is said on stderr, the
    workspace left where it was, and no error replaces the run's result."""
    _observed_head(forge, forge.head)

    def failed(self: RepoCheckoutService, workspace: object) -> None:
        raise ServiceError("release failed")

    monkeypatch.setattr(RepoCheckoutService, "release", failed)
    with session.checkout(REPO, forge.config) as workspace:
        head = _git("-C", str(workspace.path), "rev-parse", "HEAD")
        assert head == forge.head
    assert workspace.path.exists()  # left behind, said where
    assert "workspace release failed" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("observe", "because"),
    [(False, "not in the inventory"), (True, "no observed default head")],
    ids=["never registered", "head never observed"],
)
def test_a_repository_without_an_observed_head_is_refused(
    forge: Forge, observe: bool, because: str
) -> None:
    if observe:
        core = load(forge.config)
        core.services().portfolio.register_repository(
            HttpsRepoUrl.parse(REPO, core.config.forge_hosts), False
        )
    with pytest.raises(NotFoundError, match=because), session.checkout(REPO, forge.config):
        pass


def test_only_an_allowed_https_repository_is_checked_out(forge: Forge) -> None:
    with (
        pytest.raises(ValidationError, match="must be https"),
        session.checkout("http://x.io/a/b", forge.config),
    ):
        pass
    with (
        pytest.raises(ValidationError, match="host not allowed"),
        session.checkout("https://x.io/a/b", forge.config),
    ):
        pass
