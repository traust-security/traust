#!/usr/bin/env bash
# entrypoint.sh — Container entrypoint for backport-fix runs.
#
# Sets up PYTHONPATH, marks git dirs as safe, and runs the command.
# Logs and patches are written to /workspace/results (mount a volume).

set -euo pipefail

# If Amalgamator is mounted at /workspace/amalgamator, add to PYTHONPATH
if [[ -d /workspace/amalgamator/auto_bug_fix ]]; then
    export PYTHONPATH="/workspace/amalgamator:${PYTHONPATH:-}"
fi

# Mark mounted repos as safe for git
git config --global --add safe.directory '*'

# Log environment for debugging
echo "[entrypoint] Python: $(python3 --version 2>&1)"
echo "[entrypoint] PYTHONPATH: ${PYTHONPATH:-not set}"
echo "[entrypoint] CLAUDE_CODE_USE_VERTEX: ${CLAUDE_CODE_USE_VERTEX:-not set}"
echo "[entrypoint] GOOGLE_APPLICATION_CREDENTIALS: ${GOOGLE_APPLICATION_CREDENTIALS:-not set}"

# Verify Amalgamator is importable
if ! python3 -c "import auto_bug_fix" 2>/dev/null; then
    echo "[entrypoint] ERROR: Cannot import auto_bug_fix." >&2
    echo "  Mount Amalgamator at /workspace/amalgamator or bake it into the image." >&2
    exit 1
fi

exec "$@"
