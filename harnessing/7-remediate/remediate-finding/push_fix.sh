#!/usr/bin/env bash
# Deterministic commit + push for one remediate-finding patch.
#
# The agent that wrote the patch never runs a mutating git command: after
# Phase 4 the worktree holds uncommitted changes and nothing else. This
# script turns that file state into the exact commit that gets reported
# (Phase 5), reviewed (Phase 5b) and pushed (Phase 6):
#
#   commit  snapshot the worktree's FILES (.git excluded) onto a
#          fresh clone at the recorded pre-agent base commit, then commit
#          under a fixed machine identity.
#   push    push the reviewed fix commit from that clone to the fix branch on
#          the private fork, refusing unless the clone still holds exactly it.
#   discard remove a clone this script created without pushing it (a Phase 5b
#          REJECT, or an earlier iteration's clone).
#
# Why a fresh clone rather than committing in the worktree: the worktree's
# .git is agent-adjacent and shared with core's mirror, and hostile target
# build/test code can plant executable git configuration there. Committing
# would run git against that .git.
# The clone is created
# by this script in an unpredictable mktemp path, with system/global git
# config ignored (GIT_CONFIG_GLOBAL/SYSTEM=/dev/null — no url.*.insteadOf
# rewrites, no clean/smudge filters, no ambient hooks) and hooks disabled,
# and only worktree FILES — never .git — are copied onto it
# (the SCI worker's pristine-push shape, `rsync -a --delete --exclude=/.git`,
# done with python3 so no image needs another tool). The base commit is re-verified by sha after checkout, so the
# clone is exactly the audited tree plus the snapshot.
#
# Committer identity — FIXED, deliberately not any person:
#   sci-remediation <sci-remediation@localhost>
# A machine identity distinct from every human committer (and from SCI's
# `sci-worker`, a different lane) so pushed fixes are attributable to the
# harness, never to a person. Signing is disabled for the same reason: the
# identity owns no key (`commit.gpgsign=false`).
#
# `commit` runs before Phase 5, not at push time, because `assemble`
# builds the report (patch diff, files changed, fork.fix_commit) from
# committed state `audited_commit..HEAD` — the deterministic commit is the
# commit it reads, which is what makes the report describe exactly what
# Phase 6 pushes.
#
# Usage:
#   push_fix.sh commit <worktree> <audited-sha> <clone-source> <message-file> [<removals-file>]
#   push_fix.sh push   <fix-clone> <fork-url> <fix-branch> <fix-commit>
#   push_fix.sh discard <fix-clone>
#
#   <clone-source>  the private fork URL (https://github.com/<owner>/<repo>);
#                   the clone is fetched from the fork over https with the
#                   per-command env-reading credential helper. An ABSOLUTE
#                   LOCAL PATH is also accepted as the clone source for
#                   tests and air-gapped deployments: the base commit is
#                   pinned by <audited-sha> and re-verified after checkout,
#                   so the source cannot alter what gets committed.
#   <message-file>  the commit message, authored in Phase 3 in the skill's
#                   prescribed format; committed verbatim via -F.
#   <removals-file> OPTIONAL, the removal door's declaration: newline-
#                   separated repo-relative paths the fix UNTRACKS (a
#                   committed binary, a generated artifact). Validated
#                   (tracked-at-base, no traversal/.git shapes) and staged
#                   as `git rm --cached` AFTER the snapshot's `add -A`,
#                   keeping the worktree copy — the same door the SCI
#                   worker's push gives report-declared removals. An
#                   invalid declaration fails the commit loudly.
#   <fix-commit>    the `fix_commit` `commit` printed: the commit the report
#                   describes and Phase 5b reviewed. `push` pushes that exact
#                   object, and only while the clone's HEAD and sentinel name it.
#
# Env:
#   GITHUB_TOKEN    required by `commit` (https clone) and `push` — read by
#                   the per-command credential helper from the environment,
#                   never argv, never written to any config or URL.
#
# Output (stdout): one JSON object per invocation (clone/fix_commit for
# `commit`; pushed/fix_commit for `push`). Logs go to stderr.

set -euo pipefail

# Fixed machine committer — see header. Not overridable: a configurable
# identity could be pointed at a person's name/email.
COMMITTER_NAME="sci-remediation"
COMMITTER_EMAIL="sci-remediation@localhost"

# Env-reading credential helper (the skill's Phase 6 shape): the empty
# `-c credential.helper=` clears the list first, so this is the only
# helper asked, and it reads the token from the environment. The helper is
# a shell snippet git evaluates at credential time; ${GITHUB_TOKEN} must
# reach it unexpanded.
# shellcheck disable=SC2016
GH_CRED_HELPER='!f() { test "$1" = get && printf "username=x-access-token\npassword=%s\n" "${GITHUB_TOKEN:?GITHUB_TOKEN not set}"; }; f'

# Safe git (SCI worker's git_safe): system/global config ignored, hooks
# disabled, fsmonitor off — nothing an agent session or hostile target
# code planted in a config file executes in this script's context.
git_safe() {
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -c core.hooksPath=/dev/null -c core.fsmonitor= "$@"
}

snapshot_files() {
  # snapshot_files <worktree> <clone>: the `rsync -a --delete --exclude=/.git`
  # of the SCI worker. The clone's files (all but its .git) go, then the
  # worktree's (all but its top-level .git) are copied in: regular files with
  # their modes, symlinks as links, directories walked. Each entry is opened
  # (O_NOFOLLOW, O_NONBLOCK) relative to its parent's descriptor and classified
  # by fstat on what was opened, so target code swapping an entry mid-copy can't
  # make the snapshot follow a symlink out of the worktree or read a FIFO or a
  # device (/dev/zero reads forever): anything but a regular file, directory or
  # symlink fails the snapshot before a byte of it is read.
  # Directory jobs retain identities, not descriptors. Reopening each component
  # from the pinned root bounds the FD budget independently of nesting depth;
  # a changed ancestor is refused, never followed through an absolute pathname.
  python3 - "$1" "$2" <<'PY'
import errno, os, shutil, stat, sys
src, dst = sys.argv[1:]
for name in os.listdir(dst):
    if name != ".git":
        path = os.path.join(dst, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.unlink(path)

OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)

def copy_file(fd, d, mode):
    out = os.open(d, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        while chunk := os.read(fd, 1 << 20):
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(out, remaining)
                if written <= 0:
                    sys.exit(f"[push_fix] snapshot write made no progress: {d}")
                remaining = remaining[written:]
        os.fchmod(out, stat.S_IMODE(mode))
    finally:
        os.close(out)


def refuse(s):
    sys.exit(f"[push_fix] not a regular file, directory or symlink: {s}")

def copy_entry(parent, name, s, d):
    try:
        fd = os.open(name, OPEN, dir_fd=parent)
    except OSError as e:
        if e.errno in (errno.ENXIO, errno.EOPNOTSUPP, errno.ENODEV):  # a socket or device
            refuse(s)
        if e.errno != errno.ELOOP:  # O_NOFOLLOW: ELOOP is a symlink
            raise
        os.symlink(os.readlink(name, dir_fd=parent), d)
        return
    try:
        opened = os.fstat(fd)
        mode = opened.st_mode
        if stat.S_ISDIR(mode):
            os.mkdir(d)
            return (name, opened.st_dev, opened.st_ino), stat.S_IMODE(mode)
        elif stat.S_ISREG(mode):
            copy_file(fd, d, mode)
        else:
            refuse(s)
    finally:
        os.close(fd)

def open_dir(components):
    fd = os.dup(root)
    try:
        for name, device, inode in components:
            try:
                child = os.open(name, OPEN, dir_fd=fd)
            except OSError as e:
                sys.exit(f"[push_fix] source directory changed during snapshot: {name}: {e}")
            os.close(fd)
            fd = child
            opened = os.fstat(fd)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (device, inode):
                sys.exit(f"[push_fix] source directory changed during snapshot: {name}")
        return fd
    except BaseException:
        os.close(fd)
        raise

root = os.open(src, OPEN | os.O_DIRECTORY)
try:
    if not stat.S_ISDIR(os.fstat(root).st_mode):
        refuse(src)
    # None marks a destination-mode job, applied only after its descendants.
    pending = [((), dst, None)]
    while pending:
        components, directory, mode = pending.pop()
        if components is None:
            os.chmod(directory, mode)
            continue
        parent = open_dir(components)
        try:
            for name in sorted(os.listdir(parent)):
                if name == ".git" and not components:
                    continue
                s = os.path.join(src, *(part[0] for part in components), name)
                d = os.path.join(directory, name)
                child = copy_entry(parent, name, s, d)
                if child is not None:
                    identity, child_mode = child
                    pending.append((None, d, child_mode))
                    pending.append(((*components, identity), d, None))
        finally:
            os.close(parent)
finally:
    os.close(root)
PY
}

emit_json() {
  # emit_json <key> <value> ... — argv via json.dumps, never printf into a
  # template (crafted values injecting fields: audit F8, plan P2.15)
  python3 - "$@" <<'PY'
import json, sys
print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))
PY
}

# The clone `commit` is building, removed if it exits before finishing. The trap
# names a function and the path stays in a variable: a path (from TMPDIR) is
# never parsed as shell code.
PARTIAL_CLONE=""
remove_partial_clone() {
  if [ -n "$PARTIAL_CLONE" ]; then
    chmod -R u+w -- "$PARTIAL_CLONE" 2>/dev/null || true
    rm -rf -- "$PARTIAL_CLONE"
  fi
}

usage() {
  echo "usage: push_fix.sh commit <worktree> <audited-sha> <clone-source> <message-file> [<removals-file>]" >&2
  echo "       push_fix.sh push <fix-clone> <fork-url> <fix-branch> <fix-commit>" >&2
  echo "       push_fix.sh discard <fix-clone>" >&2
  exit 1
}

[ $# -ge 1 ] || usage
MODE="$1"; shift

# ---------------------------------------------------------------- commit ----
do_commit() {
  local WORKTREE="${1:?}" SHA="${2:?}" CLONE_SRC="${3:?}" MSG="${4:?}" REMOVALS="${5:-}"
  local CLONE PDIR HEAD_REV STAGED_REMOVALS=0 SEEN_REMOVALS="" path

  [ -d "$WORKTREE" ] || { echo "[push_fix] worktree is not a directory: $WORKTREE" >&2; exit 1; }
  # a sha, not a ref: this value reaches `git checkout` and must never
  # resolve as an option or a branch name (same gate as ensure_fork.sh)
  if [[ ! "$SHA" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "[push_fix] audited-sha must be 7-40 hex chars: $SHA" >&2
    exit 1
  fi
  [ -f "$MSG" ] || { echo "[push_fix] message file not found: $MSG" >&2; exit 1; }
  [ -s "$MSG" ] || { echo "[push_fix] message file is empty: $MSG" >&2; exit 1; }
  head -n1 "$MSG" | grep -q '[^[:space:]]' || {
    echo "[push_fix] message file has no subject line: $MSG" >&2; exit 1; }

  case "$CLONE_SRC" in
    https://*)
      # fork URL gate: https on github.com only (pilot parity with
      # ensure_fork.sh), no embedded credentials (user:pass@ / token@)
      if [[ ! "$CLONE_SRC" =~ ^https://github\.com/([^/@[:space:]]+)/([^/@[:space:]]+)$ ]]; then
        echo "[push_fix] clone source must be https://github.com/<owner>/<repo> — got: $CLONE_SRC" >&2
        exit 1
      fi
      : "${GITHUB_TOKEN:?GITHUB_TOKEN must be set to clone the private fork}"
      export GIT_ALLOW_PROTOCOL=https  # https transport only (plan P0.1)
      ;;
    /*)
      # local mirror (tests, air-gapped deployments): integrity is pinned
      # by the recorded sha, re-verified after checkout below
      [ -d "$CLONE_SRC" ] || { echo "[push_fix] local clone source is not a directory: $CLONE_SRC" >&2; exit 1; }
      ;;
    *)
      echo "[push_fix] clone source must be an https URL or an absolute local path: $CLONE_SRC" >&2
      exit 1
      ;;
  esac

  # Fresh clone in an unpredictable mktemp path (never inside the
  # worktree, never a fixed squattable path). The `-c` options are
  # invocation-scoped (they precede the subcommand), so nothing — helper
  # included — is persisted into the clone's config.
  PDIR="$(mktemp -d "${TMPDIR:-/tmp}/traust-fix-clone.XXXXXX")"
  CLONE="$PDIR/repo"
  # a commit that fails part-way leaves no copy of the worktree behind
  PARTIAL_CLONE="$PDIR"
  trap remove_partial_clone EXIT
  if [[ "$CLONE_SRC" == https://* ]]; then
    git_safe -c credential.helper= -c credential.helper="$GH_CRED_HELPER" \
      clone --quiet "$CLONE_SRC" "$CLONE" >&2
  else
    git_safe clone --quiet "$CLONE_SRC" "$CLONE" >&2
  fi
  git_safe -C "$CLONE" checkout --quiet "$SHA" -- >&2
  HEAD_REV="$(git_safe -C "$CLONE" rev-parse HEAD)"
  if [[ "$HEAD_REV" != "$(printf '%s' "$SHA" | tr 'A-F' 'a-f')"* ]]; then
    echo "[push_fix] clone HEAD $HEAD_REV is not the recorded base $SHA — refusing" >&2
    exit 1
  fi

  # File-level snapshot: worktree FILES only, never .git (the worktree's
  # .git is a file naming the mirror's gitdir; excluded either way).
  snapshot_files "$WORKTREE" "$CLONE"

  # Commit exactly the snapshot under the fixed identity, dated as the base
  # commit: the same snapshot always makes the same commit, so a retry pushes
  # the object already on the fix branch instead of a non-fast-forward one.
  local BASE_DATE
  BASE_DATE="$(git_safe -C "$CLONE" log -1 --format=%cd --date=raw HEAD)"
  git_safe -C "$CLONE" add -A

# Declared-removal staging: the removal door's rationale and semantics
# are documented in SKILL.md ("Untracking a file is declarable") and in
# tests/test_remediation_deterministic_push.py. Fail-closed: an invalid
# declaration fails the commit (assemble derives files_changed from it).
  if [ -n "$REMOVALS" ]; then
    [ -f "$REMOVALS" ] || { echo "[push_fix] removals file not found: $REMOVALS" >&2; exit 1; }
    # The audited base tree, listed ONCE with core.quotePath=false so
    # non-ASCII filenames print as their raw bytes (the default C-style
    # quoting would make an exact match against the declaration
    # impossible). Matched per declaration as an EXACT line — never
    # handing git's pathspec-taking commands an agent-authored string.
    local BASE_TREE
    BASE_TREE="$(git_safe -c core.quotePath=false -C "$CLONE" ls-tree -r --name-only "$SHA")"
    # '|| [ -n "$path" ]': a final declaration without a trailing newline
    # is still a declaration — read alone would silently drop it.
    while IFS= read -r path || [ -n "$path" ]; do
      [ -n "$path" ] || continue
      # Belt: textual shape before anything touches git — traversal
      # (a whole ".." SEGMENT, so a ".." inside a filename like
      # notes/v1..v2.md passes), .git-targeting, pathspec/glob
      # metacharacters, leading ':'/'-' shapes and control characters.
      # Non-ASCII printable bytes pass (locale-stable in C).
      case "$path" in
        /*|..|../*|*/../*|*/..|.git|.git/*|*/.git|*/.git/*|-*|:*|*"*"*|*"?"*|*"["*|*\\*|*[[:cntrl:]]*)
          echo "[push_fix] refusing declared removal with unsafe path shape: $path" >&2; exit 1 ;;
      esac
      # A duplicate declaration is one removal: skip it instead of
      # falling into the not-currently-staged branch and inflating
      # removals_staged past the actual removal count.
      case " $SEEN_REMOVALS " in
        *" $path "*) continue ;;
      esac
      SEEN_REMOVALS="$SEEN_REMOVALS $path"
      # Here-string, never a pipe: under pipefail an early grep -q match
      # closes the pipe mid-listing and SIGPIPE turns a successful match
      # into a failed pipeline (large trees, early-sorted paths).
      if ! grep -qxF -- "$path" <<< "$BASE_TREE"; then
        echo "[push_fix] refusing declared removal of a path not tracked at the audited base: $path" >&2; exit 1
      fi
      if git_safe -C "$CLONE" ls-files --error-unmatch -- ":(literal)$path" >/dev/null 2>&1; then
        git_safe -C "$CLONE" rm --cached -q -- ":(literal)$path" >&2
      else
        echo "[push_fix] declared removal already staged by the worktree state: $path" >&2
      fi
      echo "[push_fix] staged declared removal (untracked, worktree copy kept): $path" >&2
      STAGED_REMOVALS=$((STAGED_REMOVALS + 1))
    done < "$REMOVALS"
  fi

  if git_safe -C "$CLONE" diff --cached --quiet; then
    echo "[push_fix] snapshot matches the audited commit — nothing to commit; a patch that changed nothing means the flow went wrong" >&2
    exit 1
  fi
  # GIT_AUTHOR_*/GIT_COMMITTER_* in the caller's environment outrank user.*
  # config, so the fixed identity is set there too: no inherited name reaches
  # the commit.
  GIT_AUTHOR_NAME="$COMMITTER_NAME" GIT_AUTHOR_EMAIL="$COMMITTER_EMAIL" \
  GIT_COMMITTER_NAME="$COMMITTER_NAME" GIT_COMMITTER_EMAIL="$COMMITTER_EMAIL" \
  GIT_AUTHOR_DATE="$BASE_DATE" GIT_COMMITTER_DATE="$BASE_DATE" \
  git_safe -C "$CLONE" \
    -c "user.name=$COMMITTER_NAME" -c "user.email=$COMMITTER_EMAIL" \
    -c commit.gpgsign=false \
    commit --quiet --no-verify -F "$MSG" >&2
  HEAD_REV="$(git_safe -C "$CLONE" rev-parse HEAD)"

  # Sentinel in the mktemp parent (outside the repo, so it is never
  # committed): `push` only drives clones this script created.
  printf 'created_by=push_fix.sh\nbase=%s\nfix_commit=%s\n' "$SHA" "$HEAD_REV" \
    > "$PDIR/.traust-fix-clone"
  PARTIAL_CLONE=""
  trap - EXIT

  emit_json clone "$CLONE" fix_commit "$HEAD_REV" base_commit "$SHA" \
    worktree "$WORKTREE" committer "$COMMITTER_NAME <$COMMITTER_EMAIL>" \
    removals_staged "$STAGED_REMOVALS"
}

# ------------------------------------------------------------ clone gate ---
# Only clones this script created: an absolute <mktemp parent>/repo path with
# the sentinel beside it. Prints the parent.
script_clone() {
  local CLONE="$1" PARENT
  [[ "$CLONE" == /* ]] || { echo "[push_fix] fix clone must be an absolute path: $CLONE" >&2; exit 1; }
  [ "$(basename "$CLONE")" = "repo" ] || {
    echo "[push_fix] not a push_fix.sh clone directory: $CLONE" >&2; exit 1; }
  PARENT="$(dirname "$CLONE")"
  case "$(basename "$PARENT")" in
    traust-fix-clone.*) ;;
    *) echo "[push_fix] not a push_fix.sh clone directory: $CLONE" >&2; exit 1;;
  esac
  [ -f "$PARENT/.traust-fix-clone" ] || {
    echo "[push_fix] missing clone sentinel — refusing to use $CLONE" >&2; exit 1; }
  printf '%s\n' "$PARENT"
}

remove_clone() {
  local CLONE="$1" PARENT="$2"
  chmod -R u+w "$PARENT" 2>/dev/null || true
  rm -rf -- "$CLONE" "$PARENT/.traust-fix-clone"
  rmdir "$PARENT" 2>/dev/null || true
}

# ----------------------------------------------------------------- push -----
do_push() {
  local CLONE="${1:?}" FORK_URL="${2:?}" FIX_BRANCH="${3:?}" FIX_COMMIT="${4:?}"
  local PARENT RECORDED HEAD_REV

  # push target gate: https on github.com only (pilot parity with
  # ensure_fork.sh), no embedded credentials — same shape as `commit`'s
  # clone-source gate; the fork URL is never a local path.
  if [[ ! "$FORK_URL" =~ ^https://github\.com/([^/@[:space:]]+)/([^/@[:space:]]+)$ ]]; then
    echo "[push_fix] fork URL must be https://github.com/<owner>/<repo> — got: $FORK_URL" >&2
    exit 1
  fi
  # git's own ref-name validator (cannot be spoofed into option parsing:
  # the argument is always prefixed with refs/heads/)
  git_safe check-ref-format "refs/heads/${FIX_BRANCH}" 2>/dev/null || {
    echo "[push_fix] unsafe fix branch name: $FIX_BRANCH" >&2; exit 1; }
  [[ "$FIX_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
    echo "[push_fix] fix-commit must be the full 40-hex sha commit printed: $FIX_COMMIT" >&2; exit 1; }

  PARENT="$(script_clone "$CLONE")"
  # The reviewed commit, and nothing else: the sentinel `commit` wrote and the
  # clone's HEAD must both still name it, and the refspec pushes that object,
  # never whatever HEAD resolves to by then.
  RECORDED="$(sed -n 's/^fix_commit=//p' "$PARENT/.traust-fix-clone")"
  HEAD_REV="$(git_safe -C "$CLONE" rev-parse HEAD)"
  if [ "$RECORDED" != "$FIX_COMMIT" ] || [ "$HEAD_REV" != "$FIX_COMMIT" ]; then
    echo "[push_fix] clone no longer holds the reviewed commit $FIX_COMMIT (sentinel: ${RECORDED:-none}, HEAD: $HEAD_REV) — refusing to push" >&2
    exit 1
  fi

  : "${GITHUB_TOKEN:?GITHUB_TOKEN must be set to push to the private fork}"
  export GIT_ALLOW_PROTOCOL=https  # https transport only (plan P0.1)

  # NORMAL PUSH ONLY: never --force. A non-fast-forward rejection means
  # the fix branch already exists with different history — stop and let a
  # human decide; overwriting another branch's history is never this
  # script's call to re-make.
  git_safe -C "$CLONE" \
    -c credential.helper= \
    -c credential.helper="$GH_CRED_HELPER" \
    push --no-verify "$FORK_URL" "${FIX_COMMIT}:refs/heads/${FIX_BRANCH}" >&2

  # The clone held a copy of the worktree's uncommitted files (the snapshot
  # copies gitignored content too; only committed content was pushed).
  # Remove it now that the push succeeded.
  remove_clone "$CLONE" "$PARENT"
  emit_json pushed true fix_branch "$FIX_BRANCH" fork_url "$FORK_URL" \
    fix_commit "$FIX_COMMIT" clone_removed true
}

# -------------------------------------------------------------- discard -----
do_discard() {
  local CLONE="${1:?}" PARENT
  PARENT="$(script_clone "$CLONE")"
  remove_clone "$CLONE" "$PARENT"
  emit_json discarded true clone "$CLONE"
}

case "$MODE" in
  commit) [ "$#" -eq 4 ] || [ "$#" -eq 5 ] || usage; do_commit "$@";;
  push)   [ $# -eq 4 ] || usage; do_push "$@";;
  discard) [ $# -eq 1 ] || usage; do_discard "$@";;
  *)      usage;;
esac
