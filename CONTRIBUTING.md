# Contributing

## Setup

```bash
git clone https://github.com/traust-security/traust.git && cd traust
make sync      # install dependencies (uv)
make hooks     # enable the repository's git hooks for this clone
make install   # create TRAUST_CONFIG_HOME from the shipped templates
```

`make doctor` verifies the configuration and scanner toolchain; `make setup`
installs the toolchain for a profile. See [docs/setup.md](docs/setup.md) for
the full reference.

## Commit messages

Use conventional-commit style: `type(scope): subject`

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style`, `revert`

```
feat(threat-model): add pr mode
fix(triage): handle empty scanner output
build!: drop Python 3.11 support        ← breaking change
```

## Hooks

| Hook | Runs | Blocks |
|------|------|--------|
| `pre-commit` | `python3 -m traust.cli check skill-alignment` and `check skill-security` | a cross-skill contract or security-posture regression |
| `pre-push` | `python3 -m traust.cli check docs-consistency` and `check content-licenses` | docs drifted from the tree, or re-imported restrictively licensed content |

Both fail closed: a missing checker blocks too. Bypass once, in an emergency,
with `--no-verify`.

## Adding or changing a skill

Run the three checks the hooks enforce before opening a pull request, plus the
docs check if you touched Markdown, scripts or schemas:

```bash
python3 -m traust.cli check skill-alignment
python3 -m traust.cli check skill-security
python3 -m traust.cli check content-licenses
python3 -m traust.cli check docs-consistency
```

## Releasing

If your pull request has `feat:`, `fix:`, `perf:` or `!` (breaking) commits:

```bash
make bump patch|minor|major     # VERSION, pyproject.toml and version.args together
python3 release.py check
git add VERSION pyproject.toml version.args
git commit -m "chore: release X.Y.Z"
```

`VERSION`, `pyproject.toml` and `version.args` must agree; the docs-consistency
check fails when they drift. Tags follow `vX.Y.Z`.

## Upstream pins

This repo pins `traust-contracts`, `traust-ledger`, and `traust-engine` by
commit sha (`[tool.uv.sources] rev = "<sha>"`), not a release tag — a tag
needs their own release cut first, a commit doesn't. When one of them merges
a change you depend on: bump the `rev` here to that commit, `uv lock`, run
the full test suite, then open the PR. This is the end of the chain — no
other repo pins traust.

## Running tests

```bash
make test              # unit tests, parallel via pytest-xdist
uv run pytest -q       # full suite (integration tests need the scanner toolchain)
```

pytest is the only runner; `unittest discover` silently skips part of the suite.

### Native scanner coverage

`.tekton/traust-native-scanners.yaml` is the native Konflux/Pipelines-as-Code test
lane for pull requests and pushes targeting `development`. It checks out public
source without credentials or a service-account token and runs as nonroot with
all capabilities dropped. GitHub Actions and the main-branch build lanes are
unchanged. This is a separate draft proposal; Shaun's review hold remains in
effect, and it must not be auto-merged.

The full (not slim) digest-pinned uv/Python 3.12 runner provides the C compiler,
make and pkg-config used by the existing toolchain installer. The
`native-scanner-tests` profile installs only opengrep, gitleaks and Universal
Ctags. Versions and source SHA256 values come from the installed Core package's
authoritative `external-tools.yaml`, selected by the frozen dependency lock.
Universal Ctags and its static Jansson JSON dependency build in a temporary,
user-writable prefix; only the resulting ctags executable is installed. No
package-manager command or root access is needed. Gitleaks retains its upstream
checksum verification; opengrep retains the installer's documented pinned-release,
TLS-only guarantee because its upstream publishes no checksum file.
This optional test-only profile is excluded from `--all`; production installs
retain the built-in symbol-index fallback when Universal Ctags is absent.

The preflight requires exact pinned scanner versions and actual recursive JSON
symbol output from Universal Ctags, not Apple's BSD ctags or a version banner
alone. The test driver runs `tests/test_default_rule_packs.py`,
`tests/test_sweep_regression_drafts.py`, `tests/test_symbol_index.py` and its
behavioral gate regressions. It requires the scanner-backed cases to pass and
parses both pytest `-rs` reasons and JUnit identities. The existing inverse
missing-ctags test may skip **only** because Universal Ctags is installed; that
test is neither forced to run nor deleted. Every other skip fails the lane.
Task/Pipeline results contain the pass/skip summary and checked tool versions;
the task log contains pytest output and skip reasons.

To run the same lane on an already provisioned Linux host:

```bash
uv sync --frozen
export HARNESS_BIN_DIR="$HOME/.local/bin"
export PATH="$HARNESS_BIN_DIR:$PATH"
uv run bash scripts/install-toolchain.sh native-scanner-tests
uv run python scripts/test-native-scanners.py --artifacts /tmp/traust-native-scanner-results
```

For an exact nonroot container smoke of the **actual PipelineRun test script**,
run the following from this checkout with a working Docker daemon (set
`CONTAINER_RUNTIME=podman` for Podman). Commit source edits first: the smoke exports
only tracked `HEAD` source into a temporary directory, excluding deployment
credentials/configuration. No checkout, Git credentials or runtime socket is mounted.

```bash
uv run python - <<'PY'
import io
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

import yaml

repo = Path.cwd().resolve()
pipeline = yaml.safe_load((repo / ".tekton/traust-native-scanners.yaml").read_text())
task = pipeline["spec"]["pipelineSpec"]["tasks"][0]["taskSpec"]
step = next(s for s in task["steps"] if s["name"] == "test-native-scanners")
env = {e["name"]: e["value"] for e in task["stepTemplate"]["env"]}
env.update({e["name"]: e["value"] for e in step["env"]})
env.update(SUMMARY_RESULT="/workspace/summary.result", VERSIONS_RESULT="/workspace/versions.result")
bootstrap = """python - <<'COPY'
import shutil
from pathlib import Path
Path('/workspace/home').mkdir()
shutil.copytree('/input', '/workspace/source')
COPY
"""
archive = subprocess.run(
    ["git", "archive", "--format=tar", "HEAD"], check=True, stdout=subprocess.PIPE
).stdout
with tempfile.TemporaryDirectory(prefix="traust-native-ci-source-") as directory:
    source = Path(directory) / "source"
    source.mkdir(mode=0o755)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        members = [
            member for member in bundle.getmembers()
            if (root := PurePosixPath(member.name).parts[0]).casefold() != "credentials"
            and root not in {"traust.yaml", ".env"}
            and not root.startswith(".env.")
        ]
        bundle.extractall(source, members=members, filter="data")
    command = [
        os.environ.get("CONTAINER_RUNTIME", "docker"), "run", "--rm",
        "--user", "65532:65532", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--tmpfs", "/workspace:rw,exec,mode=1777",
        "--mount", f"type=bind,src={source},dst=/input,readonly",
        "--workdir", "/workspace",
    ]
    for name, value in env.items():
        command.extend(["--env", f"{name}={value}"])
    command.extend([
        step["image"], "bash", "-eu", "-c",
        bootstrap + step["script"] + '\ncat "$SUMMARY_RESULT" "$VERSIONS_RESULT"\n',
    ])
    subprocess.run(command, check=True)
PY
```

Offline official-schema validation uses Tekton's immutable upstream CRD Git blob
and the already locked YAML/jsonschema dependencies:

```bash
uv run python - <<'PY'
import base64
import json
import urllib.request
from pathlib import Path

import jsonschema
import yaml

url = ("https://api.github.com/repos/tektoncd/pipeline/git/blobs/"
       "6209511b1bb9d28aa7aac89262026b985aadac1b")
with urllib.request.urlopen(url, timeout=30) as response:
    blob = json.load(response)
crd = yaml.safe_load(base64.b64decode(blob["content"]))
schema = next(v["schema"]["openAPIV3Schema"] for v in crd["spec"]["versions"] if v["name"] == "v1")
document = yaml.safe_load(Path(".tekton/traust-native-scanners.yaml").read_text())
jsonschema.Draft7Validator(schema).validate(document)
print("Official Tekton v1 structural schema: passed")
PY
```

This is not live controller admission or scheduling evidence. Without a current
OpenShift context those remain unexercised. In the authorized target context,
first run `oc apply --dry-run=server -f .tekton/traust-native-scanners.yaml`;
then inspect the real draft PR's PaC run and task results after review.

### Isolated home in tests

`tests/conftest.py` points `HOME` at a temporary directory at import time, so
traust-core's default store (`~/.traust`) and anything else keyed on `HOME`
never touches yours. Ledger events are traust-core's `LedgerService`; its tests
live in traust-core.

## Architecture

See [README.md](README.md) for the skill catalogue and pipeline stages, and
[AGENTS.md](AGENTS.md) for the conventions every skill follows.
