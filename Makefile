.PHONY: help install test doctor setup update-vuln-dbs build-image build-tools-image lint lint-fix hooks sync status bump $(BUMP_PARTS)
.PHONY: skillsaw-lint skillsaw-fix skillsaw-badge
.PHONY: ops-up ops-down ops-reset ops-run ops-claim ops-approve ops-sh ops-scan ops-smoke ops-doctor

PROFILE    ?= secure-code-audit
CLI        := uv run python -m traust.cli.toolchain
PYTHON     ?= python3
RELEASE    := ./release.py
BUMP_PARTS := patch minor major
SKILLSAW_VERSION := 0.20.0

help: ## Show targets
	@grep -E '^[a-z][-a-z]+:.*## ' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

sync: ## Install/sync dependencies (uv)
	uv sync

test: sync ## Run unit tests (parallel via pytest-xdist)
	uv run pytest tests/ -n auto

install: ## Set up TRAUST_CONFIG_HOME (scripts/install_traust; pass ARGS="--yes …" for CI)
	bash scripts/install_traust $(ARGS)

doctor: ## Verify readiness: config estate loads + toolchain for PROFILE
	bash scripts/install_traust --doctor --toolchain $(PROFILE) $(ARGS)

setup: sync ## Install toolchain for PROFILE
	$(CLI) setup --profile $(PROFILE)

update-vuln-dbs: ## Download/update vulnerability DBs for PROFILE
	$(CLI) fetch-dbs --profile $(PROFILE)

build-image: ## Build traust-toolchain (scanner binaries) and traust-runtime (FROM it, by digest)
	bash scripts/build-toolchain-image.sh

build-tools-image: ## Build only traust-toolchain (scanner binaries, no Python stack)
	bash scripts/build-toolchain-image.sh --tools-only

lint: ## ruff check + format --check
	uv run ruff check .
	uv run ruff format --check .

lint-fix: ## ruff --fix + format
	uv run ruff check --fix .
	uv run ruff format .

ops-up: ## Local continuous-ops rig: Postgres + config home + compressed pack
	bash scripts/local_ops.sh up
ops-down: ## Stop the rig's Postgres (data kept)
	bash scripts/local_ops.sh down
ops-reset: ## Fresh rig: drop the volume, regenerate config and overlay pack
	bash scripts/local_ops.sh reset
ops-run: ## Engine tick loop, pane 1 (make ops-run OPS_EVERY=5m)
	bash scripts/local_ops.sh run
ops-claim: ## Claim loop, pane 2
	bash scripts/local_ops.sh claim
ops-approve: ## Operator door: approve awaiting orders (all, or one by an unambiguous id prefix)
	bash scripts/local_ops.sh approve '$(ORDER)'
ops-sh: ## Shell with the rig's environment (TRAUST_CONFIG_HOME, .local-ops/env)
	bash scripts/local_ops.sh sh
ops-scan: ## Walk the workflow by hand: onboard + observe + one scan (REPO=https://...)
	bash scripts/local_ops.sh scan $(REPO)
ops-smoke: ## One bounded engine cycle with asserts (the CI entry)
	bash scripts/local_ops.sh smoke
ops-doctor: ## Check the rig: container, engine, config home, tokens
	bash scripts/local_ops.sh doctor

skillsaw-badge: ## Regenerate the committed skillsaw grade badge (Podman)
	podman run --rm -v "$(CURDIR):/workspace:Z" ghcr.io/stbenjam/skillsaw:v$(SKILLSAW_VERSION) badge

skillsaw-lint: skillsaw-badge ## Lint agent context with version-pinned skillsaw (Podman)
	podman run --rm -v "$(CURDIR):/workspace:Z" ghcr.io/stbenjam/skillsaw:v$(SKILLSAW_VERSION) --strict

skillsaw-fix: ## Apply safe skillsaw autofixes (Podman)
	podman run --rm -v "$(CURDIR):/workspace:Z" ghcr.io/stbenjam/skillsaw:v$(SKILLSAW_VERSION) fix

hooks: ## Enable .githooks for this clone
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

status: ## Current version, tag, git state
	$(PYTHON) $(RELEASE) status

$(BUMP_PARTS):
	@:

bump: ## Bump VERSION + pyproject.toml: make bump patch|minor|major
	@part="$(filter $(BUMP_PARTS),$(MAKECMDGOALS))"; \
	if [ -z "$$part" ]; then \
		echo "usage: make bump patch|minor|major" >&2; \
		exit 1; \
	fi; \
	$(PYTHON) $(RELEASE) bump $$part
