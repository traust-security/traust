.PHONY: help install test doctor setup update-vuln-dbs build-image build-tools-image lint lint-fix hooks sync
.PHONY: skillsaw-lint skillsaw-fix skillsaw-badge
.PHONY: ops-up ops-down ops-reset ops-run ops-claim ops-approve ops-approve-all ops-sh ops-scan ops-smoke ops-doctor
.PHONY: ops-check-pins ops-smoke-probe

PROFILE    ?= secure-code-audit
CLI        := uv run python -m traust.cli.toolchain
SKILLSAW_VERSION := 0.20.0
# ops-approve's selector travels through the environment (never interpolated
# into the recipe text): a value carrying quotes or semicolons reaches the
# script as one literal argument for cmd_approve to validate, not as shell
# syntax the recipe would execute.
# Keep Make expressions literal too; export must not evaluate a selector.
override ORDER := $(value ORDER)
export ORDER

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
ops-approve: ## Operator door: approve exactly one awaiting order (ORDER=<unambiguous id prefix>)
	bash scripts/local_ops.sh approve "$$ORDER"
ops-approve-all: ## Operator door: explicitly approve all awaiting orders
	bash scripts/local_ops.sh approve --all
ops-sh: ## Shell with the rig's environment (TRAUST_CONFIG_HOME, .local-ops/env)
	bash scripts/local_ops.sh sh
ops-scan: ## Walk the workflow by hand: onboard + observe + one scan (REPO=https://...)
	bash scripts/local_ops.sh scan $(REPO)
ops-check-pins: ## Compare candidate build inputs with the installed, single-interpreter rig
	uv run --no-sync python scripts/check_ops_pins.py
ops-smoke: ## Require clean pins, disposable smoke, named rollback/reclaim and SDK recording
	@set -eu; : "$${OPS_ENGINE_CHECKOUT:?set OPS_ENGINE_CHECKOUT}" "$${OPS_SDK_CHECKOUT:?set OPS_SDK_CHECKOUT}"; \
	if [ -n "$${PYTHONPATH:-}$${PYTHONHOME:-}" ]; then echo 'strict smoke: unset PYTHONPATH/PYTHONHOME' >&2; exit 1; fi; \
	engine=$$(cd "$$OPS_ENGINE_CHECKOUT" && pwd -P); sdk=$$(cd "$$OPS_SDK_CHECKOUT" && pwd -P); \
	engine_sha=$$(git -C "$$engine" rev-parse 'HEAD^{commit}'); \
	sdk_sha=$$(git -C "$$sdk" rev-parse 'HEAD^{commit}'); \
	dirty=$$(git status --porcelain -uall); \
	if [ -n "$$dirty" ]; then printf 'CLI differs from candidate commit:\n%s\n' "$$dirty" >&2; exit 1; fi; \
	cli_sha=$$(git rev-parse 'HEAD^{commit}'); \
	tmp=$$(mktemp -d); trap 'rm -rf -- "$$tmp"' EXIT; \
	git init -q --template= "$$tmp/cli"; \
	git -C "$$tmp/cli" fetch -q --no-tags --depth=1 "$$PWD" "$$cli_sha"; \
	git -C "$$tmp/cli" checkout -q --detach "$$cli_sha"; \
	mkdir "$$tmp/home"; cd "$$tmp/cli"; \
	env -i PATH="$${HARNESS_BIN_DIR:-$$HOME/.local/bin}:$$PATH" HOME="$$tmp/home" \
	    XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-}" OPS_PORT="$${OPS_PORT:-5433}" \
	    GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=https \
	    OPS_ENGINE_CHECKOUT="$$engine" OPS_SDK_CHECKOUT="$$sdk" OPS_SDK_REV="$$sdk_sha" OPS_ACCEPTANCE=1 \
	    OPS_ENGINE_SRC="git+https://github.com/traust-security/traust-engine.git@$$engine_sha" \
	    bash scripts/local_ops.sh smoke
ops-smoke-probe: ## Run diagnostic integrity probes; never acceptance evidence
	OPS_ACCEPTANCE=0 bash scripts/local_ops.sh smoke
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
