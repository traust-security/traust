"""`traust repo checkout`: a commit's workspace through the checkout service, its path printed
for the caller. A local repository stands in for the forge (the https URL resolves to it through
git's insteadOf in an isolated HOME, which core's git keeps), and the mirror cache and every
workspace live under tmp_path."""

from __future__ import annotations

import contextlib
import io
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from traust_core.v1.models.values import GitSha
from traust_core.v1.providers import mirror
from traust_core.v1.providers.base import Acquisition, Result
from traust_core.v1.providers.forge_archive import ArchiveCheckout
from traust_core.v1.providers.mirror import MirrorCheckout
from traust_core.v1.providers.sources import Workspace

from traust.cli import repo

pytestmark = pytest.mark.requires_git

REPO = "https://github.com/example/app"
HOSTS = ("github.com",)


def _git(*argv: str, cwd: Path | None = None) -> str:
    done = subprocess.run(["git", *argv], capture_output=True, text=True, check=True, cwd=cwd)
    return done.stdout.strip()


class Forge:
    """The local repository standing in for the forge: an anchor commit, a head, and a head
    that can move past it."""

    def __init__(self, root: Path) -> None:
        self.path = root / "origin"
        _git("init", "-q", "-b", "main", str(self.path))
        for name in ("audited.py", "changed.py"):
            (self.path / name).write_text("x = 1\n")
            _git("-C", str(self.path), "add", name)
            _git(
                "-C",
                str(self.path),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                name,
            )
        self.anchor = _git("-C", str(self.path), "rev-parse", "HEAD~1")
        self.head = _git("-C", str(self.path), "rev-parse", "HEAD")
        self.config = root / "config"

    def move(self) -> str:
        """One more commit on the default branch, past the current head."""
        (self.path / "moved.py").write_text("x = 2\n")
        _git("-C", str(self.path), "add", "moved.py")
        _git(
            "-C",
            str(self.path),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "moved",
        )
        return _git("-C", str(self.path), "rev-parse", "HEAD")


@pytest.fixture
def forge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Forge:
    made = Forge(tmp_path)
    # The mirror cache root, its mirror pre-seeded so the service's first fetch reaches the
    # local repository: git's `url.insteadOf` (configured on the mirror, only a test does)
    # rewrites the https URL to it, and the fetch env's protocol allowlist widens to carry
    # the file transport that stands in for https. Workspaces land under tmp_path too.
    cache = tmp_path / "mirrors" / "github.com"
    cache.mkdir(parents=True)
    mirror_path = cache / f"{REPO.removeprefix('https://github.com/')}.git"
    _git("init", "-q", "--bare", str(mirror_path))
    _git("-C", str(mirror_path), "config", f"url.{made.path}.insteadOf", REPO)
    monkeypatch.setitem(mirror._FETCH_ENV, "GIT_ALLOW_PROTOCOL", "https:file")
    (tmp_path / "tmp").mkdir()
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    made.config.mkdir()
    (made.config / "traust.yaml").write_text(
        yaml.safe_dump(
            {
                "home": str(tmp_path / "store"),
                "locations": {"mirror_cache": str(cache.parent)},
                # the mirror's fetches and worktrees run git under the process policy, so the
                # deployment's traust.yaml must allow it for checkouts to work at all
                "process": {"allowed_binaries": ["git"]},
            }
        )
    )
    return made


def run(forge: Forge, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = repo.checkout(["--config-home", str(forge.config), *argv])
    return rc, out.getvalue()


def test_the_printed_path_is_the_commits_tree(forge: Forge) -> None:
    rc, out = run(forge, REPO, "--ref", forge.anchor)
    assert rc == 0
    path = Path(out.strip())
    assert _git("-C", str(path), "rev-parse", "HEAD") == forge.anchor
    assert (path / "audited.py").read_text() == "x = 1\n"
    assert not (path / "changed.py").exists()


def test_the_workspace_holds_the_history_since_an_anchor(forge: Forge) -> None:
    rc, out = run(forge, REPO, "--ref", forge.head, "--history", forge.anchor)
    assert rc == 0
    path = Path(out.strip())
    assert _git("-C", str(path), "rev-parse", "HEAD") == forge.head
    assert _git("-C", str(path), "diff", "--name-only", f"{forge.anchor}..HEAD") == "changed.py"


def test_a_ref_the_forge_no_longer_serves_is_not_checked_out(forge: Forge) -> None:
    rc, out = run(forge, REPO, "--ref", "f" * 40)
    assert (rc, out) == (2, "")


@pytest.mark.parametrize(
    ("raw", "history"),
    [("5", 5), ("b" * 40, GitSha.parse("b" * 40)), ("1" * 40, GitSha.parse("1" * 40))],
    ids=["a depth", "an anchor sha", "an all-digit anchor sha"],
)
def test_history_is_a_depth_or_an_anchor_sha(
    forge: Forge, monkeypatch: pytest.MonkeyPatch, raw: str, history: int | GitSha
) -> None:
    asked: list[object] = []

    def checkout(self: MirrorCheckout, request: object) -> Result[Workspace]:
        asked.append(request)
        return Result(
            Workspace(repo=request.repo, sha=request.ref, path=forge.path, provider=self.name),
            Acquisition(provider=self.name, acquired_at=datetime.now(UTC)),
        )

    monkeypatch.setattr(MirrorCheckout, "checkout", checkout)
    assert run(forge, REPO, "--ref", "b" * 40, "--history", raw)[0] == 0
    assert asked[0].history == history  # type: ignore[attr-defined]


def test_kept_files_go_to_the_forge_archive(
    forge: Forge, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[object] = []

    def checkout(self: ArchiveCheckout, request: object) -> Result[Workspace]:
        asked.append(request)
        return Result(
            Workspace(
                repo=request.repo, sha=request.ref, path=tmp_path / "kept", provider=self.name
            ),
            Acquisition(provider=self.name, acquired_at=datetime.now(UTC)),
        )

    monkeypatch.setattr(ArchiveCheckout, "checkout", checkout)
    rc, out = run(forge, REPO, "--ref", forge.head, "--keep", "go.mod", "--keep", "*.toml")
    assert rc == 0 and Path(out.strip()) == tmp_path / "kept"
    assert asked[0].keep == ("go.mod", "*.toml")  # type: ignore[attr-defined]


def test_a_keep_set_with_history_or_writes_names_the_two_clean_paths(
    forge: Forge, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(forge, REPO, "--ref", forge.head, "--keep", "go.mod", "--history", "5")[0] == 2
    assert run(forge, REPO, "--ref", forge.head, "--keep", "go.mod", "--writable")[0] == 2
    assert "git-mirror" in capsys.readouterr().err


@pytest.mark.parametrize("cite_file_url", [False, True], ids=["a path", "a file:// url"])
def test_a_local_repository_is_served_straight_off_itself(
    forge: Forge, cite_file_url: bool
) -> None:
    """The recall-benchmark canary path: a repository materialized on this machine (cited as a
    plain path or `file://…`) checks out through the same command, no mirror, no fetch."""
    origin = f"file://{forge.path}" if cite_file_url else str(forge.path)
    rc, out = run(forge, origin, "--ref", forge.anchor)
    assert rc == 0
    path = Path(out.strip())
    assert _git("-C", str(path), "rev-parse", "HEAD") == forge.anchor
    assert (path / "audited.py").read_text() == "x = 1\n"
    assert not (path / "changed.py").exists()


@pytest.mark.parametrize(
    ("url", "ref", "because"),
    [
        ("http://x.io/a/b", "b" * 40, "repo path must be absolute"),
        ("origin", "b" * 40, "repo path must be absolute"),
        (REPO, "b" * 41, "not a full lowercase git sha"),
        ("https://x.io/a/b", "b" * 40, "repo host not allowed"),
    ],
    ids=["not https", "a relative path", "not a sha", "unknown host"],
)
def test_a_request_that_cannot_be_made_is_refused(
    forge: Forge, capsys: pytest.CaptureFixture[str], url: str, ref: str, because: str
) -> None:
    assert run(forge, url, "--ref", ref)[0] == 2
    assert because in capsys.readouterr().err
