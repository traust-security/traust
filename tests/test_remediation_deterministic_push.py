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
import subprocess
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
    assert "rsync -a --delete --exclude=/.git" in s
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
