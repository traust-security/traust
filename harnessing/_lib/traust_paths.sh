# Resolve campaign paths from `locations:` in $TRAUST_CONFIG_HOME/traust.yaml.
# Source from harness scripts; requires traust importable (uv sync in traust/).
# The interpreter is $TRAUST_PYTHON, else the harness venv next to this lib,
# else python3 — so callers spawned outside an activated venv (tests, cron)
# still import traust.
_traust_py() {
  if [ -n "${TRAUST_PYTHON:-}" ]; then printf '%s' "$TRAUST_PYTHON"; return; fi
  local venv_py
  venv_py="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.venv/bin/python"
  if [ -x "$venv_py" ]; then printf '%s' "$venv_py"; else printf 'python3'; fi
}
_traust_path() {
  "$(_traust_py)" -c "
from traust.context import (
    analysis_results_dir,
    findings_tree_dir,
    load,
    workspace_dir,
)
import sys
core = load()
m = {
    'workspace': workspace_dir,
    'analysis_results': analysis_results_dir,
    'findings': findings_tree_dir,
}
print(m[sys.argv[1]](core).resolve())
" "$1"
}

traust_load_paths() {
  WS="$(_traust_path workspace)"
  AR="$(_traust_path analysis_results)"
  FINDINGS="$(_traust_path findings)"
}

# Manifest rows store paths relative to workspace or under analysis-results/.
traust_resolve_campaign_path() {
  local rel="${1:-}"
  [[ -z "$rel" ]] && return 0
  if [[ "$rel" == analysis-results/* ]]; then
    echo "$AR/${rel#analysis-results/}"
  else
    echo "$WS/$rel"
  fi
}
