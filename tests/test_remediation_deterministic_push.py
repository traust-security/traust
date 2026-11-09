"""Deterministic-commit tests for push_fix.sh (followup ask E, 2026-11-02:
"deterministic commit for the pushed fix").

The pushed fix commit must be created by the script from a file-level
snapshot of the worktree (never the worktree's .git) on a fresh clone at
the recorded pre-agent base commit, under the fixed machine identity
`sci-remediation <sci-remediation@localhost>` — never by the agent's git
in the (potentially tainted, assessment 2026-07-31 C2) worktree.

The full skill flow needs a live fork + GITHUB_TOKEN; what is testable
offline is the snapshot + commit mechanics (through the script's local
clone-source seam) and every fail-closed gate. The networked halves —
https clone from the fork, the credentialed push — are exercised only in
their rejection paths here."""

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

pytestmark = [pytest.mark.requires_git]

REPO = Path(__file__).resolve().parents[1]
PUSH_FIX = REPO / "harnessing/7-remediate/remediate-finding/push_fix.sh"

MSG = (
    "fix: fix ABC-123 — tighten input validation\n"
    "\n"
    "Reject untrusted paths before use, closing the traversal at the\n"
    "single sink the triage rationale identified.\n"
    "\n"
    "Addresses: analysis-results/triage/demo-triage.json#ABC-123\n"
    "CWEs: CWE-22\n"
)


def _git(cwd, *args):
    subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )


def _commit(cwd, msg):
    _git(
        cwd,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-qm",
        msg,
    )


def _origin_with_base(tmp_path):
    """An upstream repo with one base commit; returns (repo, base sha)."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main", str(origin))
    (origin / "app.py").write_text("hello\n")
    (origin / "README.md").write_text("readme\n")
    _git(origin, "add", "-A")
    _commit(origin, "base")
    sha = subprocess.run(
        ["git", "-C", str(origin), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return origin, sha


def _script(*args, drop_env=(), env_extra=None):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    for k in drop_env:
        env.pop(k, None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(PUSH_FIX), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


def _patched_worktree(origin, base, tmp_path):
    """A linked worktree at base (`.git` is a file, the real shape) with
    uncommitted changes: one modified, one added, one deleted file."""
    wt = tmp_path / "agent-worktree"
    _git(origin, "worktree", "add", "--quiet", "--detach", str(wt), base)
    (wt / "app.py").write_text("hello patched\n")
    (wt / "new_module.py").write_text("new\n")
    (wt / "README.md").unlink()
    return wt


def test_commit_creates_deterministic_commit(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    clone = Path(out["clone"])

    # fixed machine identity — author AND committer, never a person
    ident = subprocess.run(
        ["git", "-C", str(clone), "log", "-1", "--format=%an|%ae|%cn|%ce"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert (
        ident == "sci-remediation|sci-remediation@localhost"
        "|sci-remediation|sci-remediation@localhost"
    )
    # the commit sits directly on the recorded pre-agent base
    parent = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "HEAD^"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert parent == base
    assert out["base_commit"] == base
    assert (
        out["fix_commit"]
        == subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )
    # snapshot semantics: modification, addition AND deletion all carried
    diff = subprocess.run(
        ["git", "-C", str(clone), "diff", "--name-status", f"{base}..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "M\tapp.py" in diff
    assert "A\tnew_module.py" in diff
    assert "D\tREADME.md" in diff
    # the message is committed verbatim from the file
    body = subprocess.run(
        ["git", "-C", str(clone), "log", "-1", "--format=%B"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert body.strip() == MSG.strip()
    # not signed (fixed identity owns no key)
    assert (
        subprocess.run(
            ["git", "-C", str(clone), "log", "-1", "--format=%G?"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        == "N"
    )
    # the sentinel marks the clone as script-created (for `push`)
    assert (clone.parent / ".traust-fix-clone").is_file()
    # the worktree's .git was excluded from the snapshot: the clone's own
    # .git (a directory) is intact and the tree is clean post-commit
    assert (clone / ".git").is_dir()
    status = subprocess.run(
        ["git", "-C", str(clone), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert status == ""
    # the agent's worktree is untouched by the commit: still uncommitted
    wt_status = subprocess.run(
        ["git", "-C", str(wt), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "M app.py" in wt_status and "?? new_module.py" in wt_status


def test_commit_never_executes_git_in_the_worktree(tmp_path):
    """The worktree's .git is agent-adjacent and potentially tainted
    (assessment 2026-07-31 C2): a hostile pre-commit hook and config
    planted there must never run — the script must not execute git in the
    worktree at all."""
    origin, base = _origin_with_base(tmp_path)
    # a standalone clone as the worktree (its .git is a directory we can
    # plant hostile content into)
    wt = tmp_path / "hostile-worktree"
    subprocess.run(
        ["git", "clone", "-q", str(origin), str(wt)],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    _git(wt, "checkout", "-q", base, "--")
    (wt / "app.py").write_text("hello patched\n")
    marker = tmp_path / "hook-ran"
    hooks = wt / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
    (hooks / "pre-commit").chmod(0o755)
    _git(wt, "config", "--local", "core.fsmonitor", "/tmp/evil-fsmonitor")
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    assert not marker.exists(), "a hook from the worktree's .git executed"
    out = json.loads(r.stdout.strip().splitlines()[-1])
    clone = Path(out["clone"])
    # hostile local config did not transfer to the clone
    cfg = subprocess.run(
        ["git", "-C", str(clone), "config", "--local", "--list"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "fsmonitor" not in cfg
    # the commit exists — git ran only in the fresh clone
    assert (
        subprocess.run(
            ["git", "-C", str(clone), "log", "-1", "--format=%an"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        == "sci-remediation"
    )


def test_commit_refuses_empty_diff(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = tmp_path / "clean-worktree"
    _git(origin, "worktree", "add", "--quiet", "--detach", str(wt), base)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 1
    assert "nothing to commit" in r.stderr


@pytest.mark.parametrize(
    "sha",
    ["--upload-pack=evil", "HEAD", "main", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"],
)
def test_commit_rejects_bad_sha(tmp_path, sha):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script("commit", str(wt), sha, str(origin), str(msg))
    assert r.returncode == 1
    assert "audited-sha" in r.stderr


@pytest.mark.parametrize(
    "src",
    [
        "ext::sh -c 'touch /tmp/pwned'",
        "ssh://git@github.com/org/repo.git",
        "http://github.com/org/repo",
        "https://user:tok@github.com/org/repo",
        "relative/path",
    ],
)
def test_commit_rejects_bad_clone_source(tmp_path, src):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script("commit", str(wt), base, src, str(msg))
    assert r.returncode == 1
    assert "clone source" in r.stderr


def test_commit_rejects_bad_message_file(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)

    missing = _script("commit", str(wt), base, str(origin), str(tmp_path / "nope.txt"))
    assert missing.returncode == 1
    assert "message file not found" in missing.stderr

    empty = tmp_path / "empty.txt"
    empty.write_text("")
    r = _script("commit", str(wt), base, str(origin), str(empty))
    assert r.returncode == 1
    assert "message file is empty" in r.stderr

    blank_subject = tmp_path / "blank-subject.txt"
    blank_subject.write_text("   \n\nbody\n")
    r = _script("commit", str(wt), base, str(origin), str(blank_subject))
    assert r.returncode == 1
    assert "no subject line" in r.stderr


def test_commit_requires_token_for_https_clone_source(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script(
        "commit",
        str(wt),
        base,
        "https://github.com/org/fork",
        str(msg),
        drop_env=("GITHUB_TOKEN",),
    )
    # `:` unset guard fires before any network attempt
    assert r.returncode != 0
    assert "GITHUB_TOKEN" in r.stderr


@pytest.mark.parametrize("branch", ["bad branch name", "fix/../evil", "fix/evil/", "fix/evil.lock"])
def test_push_rejects_unsafe_branch(tmp_path, branch):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    made = json.loads(r.stdout.strip().splitlines()[-1])

    r = _script("push", made["clone"], "https://github.com/org/fork", branch, made["fix_commit"])
    assert r.returncode == 1
    assert "fix branch" in r.stderr


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/org/fork",
        "https://user:tok@github.com/org/fork",
        "ssh://git@github.com/org/fork.git",
        str(Path("/some/local/path")),
    ],
)
def test_push_rejects_non_https_fork_url(tmp_path, url):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    made = json.loads(r.stdout.strip().splitlines()[-1])

    r = _script("push", made["clone"], url, "fix/abc/some-slug", made["fix_commit"])
    assert r.returncode == 1
    assert "fork URL" in r.stderr


def test_push_rejects_directory_that_is_not_a_script_clone(tmp_path):
    # a plain repo directory: no mktemp parent, no sentinel — refused
    # even with a valid https fork URL (the push gate never widens)
    origin, _base = _origin_with_base(tmp_path)
    r = _script("push", str(origin), "https://github.com/org/fork", "fix/abc/some-slug", "a" * 40)
    assert r.returncode == 1
    assert "not a push_fix.sh clone" in r.stderr


def test_push_requires_token(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    made = json.loads(r.stdout.strip().splitlines()[-1])

    r = _script(
        "push",
        made["clone"],
        "https://github.com/org/fork",
        "fix/abc/some-slug",
        made["fix_commit"],
        drop_env=("GITHUB_TOKEN",),
    )
    assert r.returncode != 0
    assert "GITHUB_TOKEN" in r.stderr


# ---- source-level gates (cheap, loud on regression — the idiom of
# test_p2_hardening.py; the networked halves cannot run here) -------------


def test_push_fix_source_gates():
    s = PUSH_FIX.read_text()
    # fixed machine committer, distinct from any human, and unsigned
    assert 'COMMITTER_NAME="sci-remediation"' in s
    assert 'COMMITTER_EMAIL="sci-remediation@localhost"' in s
    assert "-c commit.gpgsign=false" in s
    assert "--no-verify" in s
    # the file snapshot: worktree files only, never .git
    assert 'if name != ".git"' in s and 'if name == ".git"' in s  # .git never copied or removed
    # no tool an image may lack: the snapshot is python3, never an rsync call
    assert not re.search(r"^\s*rsync\s", s, re.M) and "command -v rsync" not in s
    # git runs hardened: ambient system/global config and hooks ignored
    assert "GIT_CONFIG_GLOBAL=/dev/null" in s and "GIT_CONFIG_SYSTEM=/dev/null" in s
    assert "core.hooksPath=/dev/null" in s
    # https-only git transport, gated at the URL validation sites
    assert "GIT_ALLOW_PROTOCOL=https" in s
    assert "https://github\\.com" in s
    # credential isolation: the list is cleared before the env-reading
    # helper is added, on clone and push alike
    assert s.count("credential.helper=") >= 4
    # normal pushes only — the push verb never carries a force flag
    # (the prose "never --force" documents the refusal)
    assert "push --force" not in s
    # the pushed object is the reviewed commit, never HEAD at push time
    assert '"${FIX_COMMIT}:refs/heads/${FIX_BRANCH}"' in s
    assert "HEAD:refs/heads" not in s
    assert "push -f " not in s
    # the identity is documented as deliberately not a person
    assert "deliberately not any person" in s


def test_skill_md_confines_the_agent_away_from_committing():
    s = (REPO / "harnessing/7-remediate/remediate-finding/SKILL.md").read_text()
    # the agent holds no mutating-git grants: enforcement, not just prose
    assert "Bash(git commit:*)" not in s
    assert "Bash(git add:*)" not in s
    assert "Bash(bash *push_fix.sh:*)" in s
    # nor through `git -C <dir>`: only read-only -C subcommands are granted
    assert "Bash(git -C:*)" not in s
    assert "Bash(git checkout:*)" not in s  # checkout would rewrite the worktree's edits
    assert "Bash(git -C * diff:*)" in s
    # the deterministic-commit phase exists and the push is script-driven
    assert "Phase 4d — Deterministic commit" in s
    assert "Do **not** commit" in s
    assert "push_fix.sh push" in s
    # the review gate still blocks the push
    assert "REJECT blocks the push" in s


def _committed(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_push_refuses_a_clone_that_moved_after_review(tmp_path):
    made = _committed(tmp_path)
    clone = Path(made["clone"])
    (clone / "app.py").write_text("changed after review\n")
    _git(clone, "add", "-A")
    _commit(clone, "smuggled")  # HEAD moves off the reviewed commit

    r = _script(
        "push",
        str(clone),
        "https://github.com/org/fork",
        "fix/abc/some-slug",
        made["fix_commit"],
        env_extra={"GITHUB_TOKEN": "t"},
    )
    assert r.returncode == 1
    assert "no longer holds the reviewed commit" in r.stderr


def test_push_refuses_a_commit_other_than_the_one_recorded(tmp_path):
    made = _committed(tmp_path)
    other = "b" * 40
    r = _script(
        "push",
        made["clone"],
        "https://github.com/org/fork",
        "fix/abc/some-slug",
        other,
        env_extra={"GITHUB_TOKEN": "t"},
    )
    assert r.returncode == 1
    assert "no longer holds the reviewed commit" in r.stderr


@pytest.mark.parametrize("commit", ["", "HEAD", "abc1234", "--force"])
def test_push_needs_the_full_reviewed_sha(tmp_path, commit):
    made = _committed(tmp_path)
    r = _script("push", made["clone"], "https://github.com/org/fork", "fix/abc/some-slug", commit)
    assert r.returncode == 1


def test_discard_removes_an_unpushed_clone_and_only_one_this_script_made(tmp_path):
    made = _committed(tmp_path)
    parent = Path(made["clone"]).parent
    r = _script("discard", made["clone"])
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["discarded"] == "true"
    assert not parent.exists()

    (tmp_path / "other").mkdir()
    origin, _ = _origin_with_base(tmp_path / "other")
    refused = _script("discard", str(origin))
    assert refused.returncode == 1
    assert "not a push_fix.sh clone" in refused.stderr
    assert origin.exists()


def test_a_failed_commit_leaves_no_clone_behind(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = tmp_path / "clean-worktree"
    _git(origin, "worktree", "add", "--quiet", "--detach", str(wt), base)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    scratch = tmp_path / "tmp"
    scratch.mkdir()

    r = _script("commit", str(wt), base, str(origin), str(msg), env_extra={"TMPDIR": str(scratch)})
    assert r.returncode == 1 and "nothing to commit" in r.stderr
    assert list(scratch.iterdir()) == []


def test_a_quote_in_tmpdir_is_never_run_as_shell_code(tmp_path):
    # the cleanup trap names a function; the path never reaches a shell parser
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    marker = tmp_path / "pwned"
    hostile = tmp_path / """q'; touch "$MARK"; '"""  # one path segment: no slash
    hostile.mkdir()
    # the prefix a broken quote leaves exists, so an injected command would run
    (tmp_path / "q").mkdir()
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()  # the clone fails, so the cleanup trap runs

    r = _script(
        "commit",
        str(wt),
        base,
        str(not_a_repo),
        str(msg),
        env_extra={"TMPDIR": str(hostile), "MARK": str(marker)},
    )
    assert r.returncode != 0
    assert not marker.exists()
    assert list(hostile.iterdir()) == []  # and the half-made clone is gone


def test_an_inherited_author_or_committer_never_reaches_the_commit(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    person = {
        "GIT_AUTHOR_NAME": "A Person",
        "GIT_AUTHOR_EMAIL": "person@example.com",
        "GIT_COMMITTER_NAME": "A Person",
        "GIT_COMMITTER_EMAIL": "person@example.com",
    }
    r = _script("commit", str(wt), base, str(origin), str(msg), env_extra=person)
    assert r.returncode == 0, r.stderr
    clone = json.loads(r.stdout.strip().splitlines()[-1])["clone"]
    who = subprocess.run(
        ["git", "-C", clone, "log", "-1", "--format=%an <%ae>|%cn <%ce>"],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    ).stdout.strip()
    machine = "sci-remediation <sci-remediation@localhost>"
    assert who == f"{machine}|{machine}"


def test_the_same_snapshot_makes_the_same_commit(tmp_path):
    # dated as the base: a retry re-creates the object already on the fix branch
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    made = [
        json.loads(_script("commit", str(wt), base, str(origin), str(msg)).stdout.splitlines()[-1])
        for _ in range(2)
    ]
    assert made[0]["fix_commit"] == made[1]["fix_commit"]


def test_the_snapshot_keeps_modes_and_links_and_refuses_special_files(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    (wt / "run.sh").write_text("#!/bin/sh\n")
    (wt / "run.sh").chmod(0o755)
    (wt / "link").symlink_to("app.py")
    (wt / "ignored.log").write_text("x\n")
    (wt / ".gitignore").write_text("*.log\n")
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    clone = json.loads(r.stdout.splitlines()[-1])["clone"]
    tree = subprocess.run(
        ["git", "-C", clone, "ls-tree", "HEAD"], capture_output=True, text=True, check=True
    ).stdout
    entries = {line.split("\t")[1]: line.split()[0] for line in tree.splitlines()}
    assert entries["run.sh"] == "100755" and entries["link"] == "120000"
    assert "ignored.log" not in entries  # gitignored content is never committed

    fifo = tmp_path / "fifo-worktree"
    _git(origin, "worktree", "add", "--quiet", "--detach", str(fifo), base)
    os.mkfifo(fifo / "pipe")
    r = _script("commit", str(fifo), base, str(origin), str(msg))
    assert r.returncode != 0


def test_a_socket_or_device_anywhere_fails_the_snapshot_before_it_is_read(tmp_path, monkeypatch):
    # a device node needs root to create; a socket is the same class (neither a regular
    # file, a directory nor a symlink), so it exercises the same refusal
    import socket

    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    deeper = wt / "nested" / "deeper"
    deeper.mkdir(parents=True)
    monkeypatch.chdir(deeper)  # bind by a short relative path: AF_UNIX paths are short
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind("s.sock")
        msg = tmp_path / "commit-message.txt"
        msg.write_text(MSG)
        r = _script("commit", str(wt), base, str(origin), str(msg))
    finally:
        server.close()
    assert r.returncode != 0
    assert "not a regular file, directory or symlink" in r.stderr
    assert "s.sock" in r.stderr


def test_a_symlink_to_a_directory_outside_is_committed_as_a_link_never_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("not part of the fix\n")
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    (wt / "escape").symlink_to(outside)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    clone = json.loads(r.stdout.splitlines()[-1])["clone"]
    tree = subprocess.run(
        ["git", "-C", clone, "ls-tree", "-r", "HEAD"], capture_output=True, text=True, check=True
    ).stdout
    entries = {line.split("\t")[1]: line.split()[0] for line in tree.splitlines()}
    assert entries["escape"] == "120000"  # the link itself
    assert not any(path.startswith("escape/") for path in entries)  # never its target's files


def _snapshot_python_env(tmp_path, wt, code):
    """Inject faults only into the real snapshot Python subprocess."""
    injection = tmp_path / "python-injection"
    injection.mkdir()
    (injection / "sitecustomize.py").write_text(
        "import os, sys\n"
        f"if len(sys.argv) == 3 and sys.argv[0] == '-' and sys.argv[1] == {str(wt)!r}:\n"
        f"    exec({textwrap.dedent(code)!r})\n"
    )
    return {"PYTHONPATH": os.pathsep.join((str(injection), os.environ.get("PYTHONPATH", "")))}


def test_short_writes_preserve_every_committed_byte(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    content = bytes(range(256)) * 8193  # more than two source-read chunks
    (wt / "payload.bin").write_bytes(content)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    env = _snapshot_python_env(
        tmp_path,
        wt,
        """
        original_write = os.write
        def short_write(fd, data):
            return original_write(fd, memoryview(data)[:65537])
        os.write = short_write
        """,
    )
    r = _script("commit", str(wt), base, str(origin), str(msg), env_extra=env)
    assert r.returncode == 0, r.stderr
    clone = json.loads(r.stdout.splitlines()[-1])["clone"]
    try:
        committed = subprocess.run(
            ["git", "-C", clone, "show", "HEAD:payload.bin"], capture_output=True, check=True
        ).stdout
        assert len(committed) == len(content)
        assert committed == content
    finally:
        _script("discard", clone)


def test_zero_progress_write_refuses_the_commit_and_cleans_the_clone(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = _snapshot_python_env(tmp_path, wt, "os.write = lambda fd, data: 0")
    env["TMPDIR"] = str(scratch)
    r = _script("commit", str(wt), base, str(origin), str(msg), env_extra=env)
    assert r.returncode != 0
    assert "write made no progress" in r.stderr
    assert not r.stdout.strip()
    assert list(scratch.iterdir()) == []


def test_deep_worktree_commits_under_a_small_descriptor_limit(tmp_path):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    nested = wt
    for _ in range(80):
        nested /= "d"
        nested.mkdir()
    nested.chmod(0o750)
    content = b"deep snapshot retains every byte\n"
    (nested / "payload.bin").write_bytes(content)
    (nested / "run.sh").write_text("#!/bin/sh\n")
    (nested / "run.sh").chmod(0o755)
    (nested / "link").symlink_to("payload.bin")
    (nested / "ignored.log").write_text("not committed\n")
    (wt / ".gitignore").write_text("*.log\n")
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    env = _snapshot_python_env(
        tmp_path,
        wt,
        """
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
        """,
    )
    r = _script("commit", str(wt), base, str(origin), str(msg), env_extra=env)
    assert r.returncode == 0, r.stderr
    clone = json.loads(r.stdout.splitlines()[-1])["clone"]
    relative = nested.relative_to(wt).as_posix()
    try:
        assert (Path(clone) / relative).stat().st_mode & 0o777 == 0o750
        committed = subprocess.run(
            ["git", "-C", clone, "show", f"HEAD:{relative}/payload.bin"],
            capture_output=True,
            check=True,
        ).stdout
        assert committed == content
        tree = subprocess.run(
            ["git", "-C", clone, "ls-tree", "HEAD", f"{relative}/"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        entries = {line.split("\t")[1]: line.split()[0] for line in tree.splitlines()}
        assert entries[f"{relative}/run.sh"] == "100755"
        assert entries[f"{relative}/link"] == "120000"
        assert f"{relative}/ignored.log" not in entries
    finally:
        _script("discard", clone)


@pytest.mark.parametrize("replacement", ["symlink", "directory", "fifo", "file"])
def test_a_swapped_ancestor_refuses_the_snapshot_without_reading_outside(tmp_path, replacement):
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    branch = wt / "branch"
    (branch / "deeper").mkdir(parents=True)
    (branch / "deeper" / "payload.bin").write_bytes(b"original\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("never read or modified\n")
    marker = tmp_path / "swap-ran"
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = _snapshot_python_env(
        tmp_path,
        wt,
        f"""
        original_open = os.open
        branch_opens = 0
        def swap_ancestor(path, flags, *args, **kwargs):
            global branch_opens
            if kwargs.get("dir_fd") is not None:
                required = os.O_NOFOLLOW | os.O_NONBLOCK
                assert flags & required == required
            if path == "branch" and kwargs.get("dir_fd") is not None:
                branch_opens += 1
                if branch_opens == 2:
                    os.rename({str(branch)!r}, {str(tmp_path / "original-branch")!r})
                    replacement = {replacement!r}
                    if replacement == "symlink":
                        os.symlink({str(outside)!r}, {str(branch)!r})
                    elif replacement == "directory":
                        os.mkdir({str(branch)!r})
                    elif replacement == "fifo":
                        os.mkfifo({str(branch)!r})
                    else:
                        with open({str(branch)!r}, "wb") as stream:
                            stream.write(b"not a directory")
                    with open({str(marker)!r}, "w") as stream:
                        stream.write("swapped")
            return original_open(path, flags, *args, **kwargs)
        os.open = swap_ancestor
        """,
    )
    env["TMPDIR"] = str(scratch)
    r = _script("commit", str(wt), base, str(origin), str(msg), env_extra=env)
    assert marker.read_text() == "swapped"
    assert r.returncode != 0
    assert "source directory changed during snapshot" in r.stderr
    assert not r.stdout.strip()
    assert list(scratch.iterdir()) == []
    assert secret.read_text() == "never read or modified\n"


# --------------------------------------------------------- removal door ----
# The declared-removal door (traust-foundry#13): untracking a file is a
# DECLARATION the deterministic side executes — the same door the SCI
# worker's pristine push gives report-declared removals. The live gap:
# work item 3cd248bd, the tracked-binary finding that honestly verdicted
# `unresolved` because no lane offered `git rm --cached`.


def _origin_with_binary(tmp_path):
    """An upstream whose base commit tracks a binary — the finding shape."""
    origin, _base = _origin_with_base(tmp_path)
    (origin / "blob.bin").write_bytes(b"BIN\x00\x01\x02\x03PAYLOAD")
    _git(origin, "add", "-A")
    _commit(origin, "add the binary")
    sha = subprocess.run(
        ["git", "-C", str(origin), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return origin, sha


def test_commit_stages_a_declared_removal(tmp_path):
    """A declared, tracked-at-base path is untracked by the commit; the
    worktree copy is kept (git rm --cached, not deletion); the removal
    rides the committed diff so `assemble` derives the deleted row."""
    origin, base = _origin_with_binary(tmp_path)
    wt = tmp_path / "agent-worktree"
    _git(origin, "worktree", "add", "--quiet", "--detach", str(wt), base)
    (wt / "app.py").write_text("hello patched\n")  # the .gitignore-side edit
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    removals = tmp_path / "declared-removals.txt"
    removals.write_text("blob.bin\n")

    r = _script("commit", str(wt), base, str(origin), str(msg), str(removals))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["removals_staged"] == "1"
    clone = Path(out["clone"])

    diff = subprocess.run(
        ["git", "-C", str(clone), "diff", "--name-status", f"{base}..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "D\tblob.bin" in diff, diff
    assert "M\tapp.py" in diff, diff
    # the binary's content never rides the textual diff (gitleaks-safe)
    numstat = subprocess.run(
        ["git", "-C", str(clone), "diff", "--numstat", f"{base}..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "-\t-\tblob.bin" in numstat, numstat
    # untracked, not deleted: the worktree copy stays on disk
    ls = subprocess.run(
        ["git", "-C", str(clone), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "blob.bin" not in ls
    assert (clone / "blob.bin").is_file()
    # the agent's worktree is untouched: the binary is still there too
    assert (wt / "blob.bin").is_file()


def test_commit_refuses_a_removal_not_tracked_at_base(tmp_path):
    """Tracked-at-base is the structural control: a session-added or
    never-existed path can never be untracked through a declaration."""
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    removals = tmp_path / "declared-removals.txt"
    removals.write_text("new_module.py\n")  # added this session, not at base

    r = _script("commit", str(wt), base, str(origin), str(msg), str(removals))
    assert r.returncode != 0
    assert "not tracked at the audited base" in r.stderr
    # a failed commit leaves no clone behind (the existing trap discipline)
    assert not list(tmp_path.glob("traust-fix-clone.*"))


@pytest.mark.parametrize("bad", ["../escape.bin", "/etc/passwd", ".git/config", "sub/../../x"])
def test_commit_refuses_unsafe_removal_shapes(tmp_path, bad):
    """Traversal, absolute and .git-targeting declarations fail closed."""
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    removals = tmp_path / "declared-removals.txt"
    removals.write_text(bad + "\n")

    r = _script("commit", str(wt), base, str(origin), str(msg), str(removals))
    assert r.returncode != 0
    assert "refusing declared removal" in r.stderr


def test_commit_without_a_removals_file_is_unchanged_behavior(tmp_path):
    """The fifth argument is optional and inert when absent: removals_staged
    reads 0 and the commit is exactly the pre-door shape."""
    origin, base = _origin_with_base(tmp_path)
    wt = _patched_worktree(origin, base, tmp_path)
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)

    r = _script("commit", str(wt), base, str(origin), str(msg))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["removals_staged"] == "0"


def test_a_declared_removal_already_satisfied_by_a_worktree_deletion(tmp_path):
    """When the agent deleted the worktree file anyway, the snapshot's
    `add -A` already staged the deletion: the declaration counts, the
    commit still lands, and nothing is double-staged."""
    origin, base = _origin_with_binary(tmp_path)
    wt = tmp_path / "agent-worktree"
    _git(origin, "worktree", "add", "--quiet", "--detach", str(wt), base)
    (wt / "app.py").write_text("hello patched\n")
    (wt / "blob.bin").unlink()
    msg = tmp_path / "commit-message.txt"
    msg.write_text(MSG)
    removals = tmp_path / "declared-removals.txt"
    removals.write_text("blob.bin\n")

    r = _script("commit", str(wt), base, str(origin), str(msg), str(removals))
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["removals_staged"] == "1"
    clone = Path(out["clone"])
    diff = subprocess.run(
        ["git", "-C", str(clone), "diff", "--name-status", f"{base}..HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert diff.count("D\tblob.bin") == 1, diff
