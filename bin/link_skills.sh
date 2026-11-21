#!/usr/bin/env bash
# Explicitly link this clone's skills into ~/.claude/skills for agent
# discovery. Extracted from the pre-commit hook (audit E8, remediation
# plan P1.8): a git hook silently modifying $HOME agent configuration is
# hostile-contributor territory for an open-source repo — linking is now
# an explicit, user-run action.
#
# Repairs as well as creates. A link can be wrong in three ways:
#
#   dangling  the target directory is gone (skill moved under a stage dir)
#   stale     the target directory still exists but holds no SKILL.md —
#             e.g. a leftover working tree at the pre-restructure path
#   correct   points at a directory that really does hold the skill
#
# The previous version guarded with `[ ! -e "$link" ]`. `-e` dereferences,
# so it saw *dangling* as absent and tried `ln -s` over an existing symlink
# (`File exists`, and with `set -e` the whole run aborted on the first one),
# while *stale* dereferenced successfully and was skipped as healthy. It
# could therefore repair neither. Fixed here by testing the link itself
# (`-L`) and validating the target actually holds a SKILL.md.
#
# Never clobbers a real file or directory, and never hijacks a link that
# resolves to a working skill in a different clone — both are reported and
# left alone.
#
# Usage: bin/link_skills.sh [--dry-run] [--prune]
#   --dry-run  report what would change, touch nothing
#   --prune    also remove links into THIS clone whose skill no longer exists
#
# bash 3.2 (macOS system bash) — no associative arrays, no `readlink -f`,
# no `ln -n`/`-h` (BSD and GNU disagree); relink is rm-then-ln.

# Deliberately no `-e`: one unlinkable skill must not abandon the other 57.
set -uo pipefail

dry_run=false
prune=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=true ;;
    --prune)   prune=true ;;
    -h|--help) sed -n '1,32p' "$0"; exit 0 ;;
    *) echo "link_skills: unknown argument '$arg'" >&2
       echo "usage: bin/link_skills.sh [--dry-run] [--prune]" >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
user_skills="${HOME}/.claude/skills"
$dry_run || mkdir -p "$user_skills"

relink() {  # relink <link> <target>
  if $dry_run; then return 0; fi
  rm -f "$1" && ln -s "$2" "$1"
}

linked=0; repaired=0; healthy=0; foreign=0; blocked=0; failed=0
# Names the main loop owns, so the orphan pass does not re-report them.
# bash 3.2: a space-delimited string stands in for a set.
handled=' '

# Two levels, because workflow skills sit under a stage directory
# (harnessing/4-triage/triage) while the rest stay at the root
# (harnessing/census) — skill-usability plan 1.2. The link name is always the
# bare skill name, so the flattened view an agent discovers is unchanged.
for skill_dir in "$repo_root"/harnessing/*/ "$repo_root"/harnessing/*/*/; do
  [ -f "$skill_dir/SKILL.md" ] || continue
  name="$(basename "$skill_dir")"
  target="${skill_dir%/}"
  link="$user_skills/$name"
  handled="${handled}${name} "

  if [ -L "$link" ]; then
    current="$(readlink "$link")"
    if [ "$current" = "$target" ] && [ -f "$current/SKILL.md" ]; then
      healthy=$((healthy+1)); continue
    fi
    # A link into some other clone that still resolves to a real skill is
    # someone else's deliberate choice — report, do not hijack.
    if [ -f "$current/SKILL.md" ]; then
      case "$current" in
        "$repo_root"/*) ;;
        *) echo "foreign:  $name -> $current (resolves elsewhere; left alone)"
           foreign=$((foreign+1)); continue ;;
      esac
    fi
    if relink "$link" "$target"; then
      echo "repaired: $name -> ${target#"$repo_root"/}"
      repaired=$((repaired+1))
    else
      echo "FAILED:   $name (could not relink)" >&2; failed=$((failed+1))
    fi
  elif [ -e "$link" ]; then
    echo "blocked:  $name is a real file or directory, not a symlink; left alone" >&2
    blocked=$((blocked+1))
  else
    if relink "$link" "$target"; then
      echo "linked:   $name -> ${target#"$repo_root"/}"
      linked=$((linked+1))
    else
      echo "FAILED:   $name (could not link)" >&2; failed=$((failed+1))
    fi
  fi
done

# Orphans: links into THIS clone that no longer resolve to a skill. The loop
# above already repaired every name that still exists, so whatever is left
# names a skill that was deleted or renamed.
orphans=0
for link in "$user_skills"/*; do
  [ -L "$link" ] || continue
  current="$(readlink "$link")"
  case "$current" in "$repo_root"/*) ;; *) continue ;; esac
  [ -f "$current/SKILL.md" ] && continue
  name="$(basename "$link")"
  case "$handled" in *" $name "*) continue ;; esac
  if $prune; then
    if $dry_run; then echo "orphan:   $name (would remove)"
    else rm -f "$link" && echo "pruned:   $name"; fi
  else
    echo "orphan:   $name -> $current (skill gone; rerun with --prune to remove)"
  fi
  orphans=$((orphans+1))
done

$dry_run && echo "link_skills: DRY RUN — nothing was changed"
echo "link_skills: ${linked} linked, ${repaired} repaired, ${healthy} already correct," \
     "${foreign} foreign, ${blocked} blocked, ${orphans} orphaned, ${failed} failed" \
     "→ $user_skills"
[ "$failed" -eq 0 ] || exit 1
