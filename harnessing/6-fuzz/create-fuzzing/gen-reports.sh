#!/usr/bin/env bash
# Render logs/<id>/*.log + clone crash artefacts into reports/<id>-fuzzing-report.md.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="${HERE}"
while [ ! -f "${HARNESS}/pyproject.toml" ] && [ "${HARNESS}" != / ]; do
  HARNESS="$(dirname "${HARNESS}")"
done
[ -f "${HARNESS}/pyproject.toml" ] || { echo "harness root not found above ${HERE}" >&2; exit 1; }
# shellcheck source=../../../_lib/traust_paths.sh
source "${HARNESS}/harnessing/_lib/traust_paths.sh"
traust_load_paths
MANIFEST="$HERE/targets.json"
CLONES="$HERE/clones"
LOGS="$HERE/logs"
REPORTS="$HERE/reports"
mkdir -p "$REPORTS"

summarise_log() { # $1=logfile → prints "execs|peak_rate|interesting|status"
  local lf="$1"
  local last status="PASS"
  last="$(grep -E '^fuzz: elapsed:' "$lf" | tail -1)"
  local execs rate interesting
  execs="$(sed -nE 's/.*execs: ([0-9]+) .*/\1/p' <<<"$last")"
  rate="$(grep -oE '\([0-9]+/sec\)' "$lf" | tr -dc '0-9\n' | sort -n | tail -1)"
  interesting="$(sed -nE 's/.*new interesting: [0-9]+ \(total: ([0-9]+)\).*/\1/p' <<<"$last")"
  grep -q '^--- FAIL' "$lf" && status="**CRASH**"
  grep -q '^signal: killed' "$lf" && status="OOM/KILLED"
  grep -qE '^(FAIL\b.*build failed|cannot find|undefined:)' "$lf" && status="BUILD-FAIL"
  [[ -z "$last" && "$status" == "PASS" ]] && status="NO-RUN"
  printf '%s|%s|%s|%s' "${execs:-0}" "${rate:-0}" "${interesting:-0}" "$status"
}

jq -r '.targets[] | @base64' "$MANIFEST" | while read -r enc; do
  t() { echo "$enc" | base64 -d | jq -r "$1"; }
  id="$(t .id)"; repo="$(t .repo)"; commit="$(t .commit)"
  clonedir="$(t '.clone_alias // .id')"
  reach="$(t .product_reach)"; audit="$(t .audit_ref)"
  goos="$(t '.goos // "any"')"; note="$(t '.note // ""')"
  out="$REPORTS/${id}-fuzzing-report.md"

  {
    echo "# ${id} — offline fuzzing report"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Repository | <$repo> @ \`${commit}\` |"
    echo "| Generated | $(date '+%Y-%m-%d %H:%M %Z') |"
    echo "| Product reach | $reach segment(s) in \`analysis-results/findings/\` |"
    echo "| Audit reference | $audit |"
    echo "| Runtime | \`go test -fuzz\` (Go $(go env GOVERSION)); host=$(go env GOOS)$( [[ "$goos" != any ]] && echo ", target requires GOOS=$goos → podman" ) |"
    [[ -n "$note" ]] && echo "| Note | $note |"
    echo
    echo "## Fuzzers"
    echo
    echo "| Fuzz func | Package | Execs | Peak execs/s | Corpus | Result |"
    echo "|---|---|--:|--:|--:|---|"

    total_crash=0
    while IFS=$'\t' read -r fn pkg; do
      lf="$LOGS/$id/$fn.log"
      if [[ -f "$lf" ]]; then
        IFS='|' read -r ex rate corp status <<<"$(summarise_log "$lf")"
      else
        ex=0; rate=0; corp=0; status="NOT-RUN"
      fi
      [[ "$status" == "CRASH" ]] && total_crash=$((total_crash+1))
      printf '| `%s` | `%s` | %s | %s | %s | %s |\n' "$fn" "$pkg" "$ex" "$rate" "$corp" "$status"
    done < <(echo "$enc" | base64 -d | jq -r '.harnesses[] | select(.fuzz!="") | [.fuzz, .pkg] | @tsv' | sort -u)

    echo
    echo "## Crash artefacts"
    echo
    crashes="$(find "$CLONES/$clonedir" -path '*/testdata/fuzz/*' -type f 2>/dev/null)"
    if [[ -n "$crashes" ]]; then
      echo "The Go fuzzer wrote the following minimised failing inputs:"
      echo
      echo '```'
      while read -r c; do
        rel="${c#$CLONES/$clonedir/}"
        echo "$rel"
      done <<<"$crashes"
      echo '```'
      echo
      echo "<details><summary>Inputs (go test fuzz v1 format)</summary>"
      echo
      while read -r c; do
        echo "### \`${c#$CLONES/$clonedir/}\`"
        echo '```'
        cat "$c"
        echo '```'
      done <<<"$crashes"
      echo "</details>"
    else
      echo "_No crashes recorded under \`testdata/fuzz/\` for this target._"
    fi

    # Known pre-recorded findings — now under analysis-results/findings/**/<id>/fuzz-corpus/
    corpus_dir="$(find "$FINDINGS" -maxdepth 3 -type d -name fuzz-corpus -path "*/$id/*" 2>/dev/null | head -1)"
    if [[ -n "$corpus_dir" ]] && compgen -G "$corpus_dir/*/*.md" >/dev/null; then
      echo
      echo "## Known findings (pre-recorded)"
      for m in "$corpus_dir"/*/*.md; do
        echo
        echo "---"
        cat "$m"
      done
    fi

    echo
    echo "## Raw logs"
    echo
    for lf in "$LOGS/$id"/*.log; do
      [[ -f "$lf" ]] || continue
      echo "<details><summary>\`$(basename "$lf")\`</summary>"
      echo
      echo '```'
      # keep reports readable: head + tail if huge
      if (( $(wc -l <"$lf") > 200 )); then
        head -60 "$lf"; echo "... [$(wc -l <"$lf") lines total] ..."; tail -60 "$lf"
      else
        cat "$lf"
      fi
      echo '```'
      echo "</details>"
      echo
    done
  } >"$out"
  echo "wrote $out"
done

# Fan reports out into analysis-results/findings/**/<id>/ next to the audit.
"$HERE/publish-reports.sh"
