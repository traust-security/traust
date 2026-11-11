#!/usr/bin/env bash
# Exhaustion sweep (bash-3.2 compatible): check out every remaining
# audit-named-fuzz-target repo through the checkout service, grep source
# for the 3 confirmed patterns, emit pattern-hits.json. Checkouts with no
# pattern match are deleted; hits stay, symlinked under clones/.
set -u   # NOTE: no pipefail — grep|head SIGPIPE (141) would kill the loop
export GIT_ALLOW_PROTOCOL=https   # belt for the https-only case gate below
RESUME_FROM="${RESUME_FROM:-1}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/pyproject.toml" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/pyproject.toml" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
_FINDINGS_OVERRIDE="${FINDINGS:-}"
# shellcheck source=../../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
[[ -n "$_FINDINGS_OVERRIDE" ]] && FINDINGS="$_FINDINGS_OVERRIDE"
CLONES="$HERE/clones"
OUT="$HERE/pattern-hits.json"
LOG="$HERE/logs/sweep-grep.log"
CANDS="$HERE/logs/sweep-grep-candidates.txt"
: >"$LOG"

log(){ printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" | tee -a "$LOG"; }

log "enumerating candidates ..."
grep -rHl -i 'fuzz' "$FINDINGS"/*/*security-audit.md "$FINDINGS"/*/*/*security-audit.md 2>/dev/null \
  | xargs grep -l -i -E '\`[^\`]+\`|pkg/|parser|decode|unmarshal|admission|regex|Fuzz[A-Z]' 2>/dev/null \
  | sed -E 's|.*/findings/[^/]+/([^/]+)/[^/]+-security-audit.md|\1|; s|.*/findings/([^/]+)/[^/]+-security-audit.md|\1|' \
  | sort -u > "$CANDS"
log "candidates: $(wc -l <"$CANDS")"

[[ "$RESUME_FROM" -le 1 ]] && echo '{"hits":[' >"$OUT"
first=$([[ "$RESUME_FROM" -le 1 ]] && echo 1 || echo 0)
hits=0; skipped=0; cloned=0; ln=0

while IFS= read -r id; do
  ln=$((ln+1)); [[ $ln -lt $RESUME_FROM ]] && continue
  [[ -z "$id" ]] && continue
  [[ $((ln % 50)) -eq 0 ]] && log "  progress $ln/889"
  [[ -d "$CLONES/$id" ]] && { skipped=$((skipped+1)); continue; }   # already handled

  jf=$(find "$FINDINGS" -name "${id}-security-audit.json" -not -type l 2>/dev/null | head -1)
  [[ -z "$jf" ]] && continue
  url=$(jq -r '.metadata.repository // empty' "$jf" 2>/dev/null | sed 's/[<>]//g; s/ .*//')
  [[ -z "$url" || "$url" == "null" ]] && continue
  case "$url" in https://github.com/*|https://gitlab.*) ;; *) continue;; esac

  work="$($(_traust_py) -m traust.cli repo checkout "$url" \
    --ref "$(git ls-remote "$url" HEAD | cut -f1)" --history 1 --writable 2>>"$LOG")" \
    || { log "clone-fail $id"; continue; }
  cloned=$((cloned+1))

  if [[ ! -f "$work/go.mod" ]] && ! ls "$work"/*/go.mod >/dev/null 2>&1; then
    rm -rf "$work"; continue
  fi

  # Pattern A: url.Parse redirect validator
  pa=$(grep -rln --include='*.go' -E 'u\.Scheme\s*==\s*""|len\(u\.Scheme\)\s*==\s*0' "$work" 2>/dev/null | xargs grep -l -E 'HasPrefix\(.*Path,\s*"/"' 2>/dev/null | grep -v vendor | head -1 | sed "s|$work/||")
  # Pattern B: sprig funcmap
  pb=$(grep -rn --include='*.go' -E 'sprig\.(Txt|Hermetic|Generic|Html)?FuncMap\(\)' "$work" 2>/dev/null | grep -v -E '/vendor/|_test\.go' | head -1 | sed "s|$work/||")

  if [[ -z "$pa" && -z "$pb" ]]; then
    rm -rf "$work"; continue
  fi
  mkdir -p "$CLONES"
  ln -sfn "$work" "$CLONES/$id"
  hits=$((hits+1))
  log "HIT $id  A=${pa:+redirect} B=${pb:+sprig}"
  [[ $first -eq 0 ]] && echo "," >>"$OUT"; first=0
  jq -n --arg id "$id" --arg url "$url" --arg a "$pa" --arg b "$pb" \
     '{id:$id,url:$url,redirect:$a,sprig:$b}' >>"$OUT"
done <"$CANDS"

echo ']}' >>"$OUT"
log "DONE — cloned=$cloned skipped-existing=$skipped hits=$hits → $OUT"
