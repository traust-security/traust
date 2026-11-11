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

### Isolated home in tests

`tests/conftest.py` points `HOME` at a temporary directory at import time, so
traust-core's default store (`~/.traust`) and anything else keyed on `HOME`
never touches yours. Ledger events are traust-core's `LedgerService`; its tests
live in traust-core.

## Architecture

See [README.md](README.md) for the skill catalogue and pipeline stages, and
[AGENTS.md](AGENTS.md) for the conventions every skill follows.
