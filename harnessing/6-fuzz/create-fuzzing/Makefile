# Offline Go-native fuzz harnesses derived from findings/**/*security-audit.md.
# No live cluster, cloud creds, or network needed beyond `make clone`.
#
# Usage:
#   make install               # copy all harness *_fuzz_test.go into clones/
#   make build                 # compile-check every harness (no fuzzing)
#   make fuzz-kube-rbac-proxy  # run one target's fuzzers for FUZZTIME
#   make fuzz-all              # run every target sequentially
#   make list                  # print target ids + fuzz func names

SHELL      := /bin/bash
# targets.json is operator-curated, but cap git transport anyway
# (audit A-class, plan P0.1): no ext::/ssh helper execution possible
export GIT_ALLOW_PROTOCOL := https
JQ         := jq
MANIFEST   ?= targets.json
CLONES     := clones
# Harness sources live in the CORPUS, not this repo: they are test code written
# ABOUT an audited repository, the same category as a finding about it. Override
# for a different workspace layout. `file:` in the manifest is relative to this.
HARNESSES  ?= ../../../../analysis-results/fuzz-harnesses
FUZZTIME   ?= 5m
GOFLAGS    ?=
# fuzz/build phases run OFFLINE — modules come from `make clone` +
# vendor/ or the module cache; a fuzz run must not be able to reach the
# network (audit C3, plan P2.11). Each recipe prefetches via sumdb-verified
# `go mod download` first, then runs tests/fuzz with GOPROXY=off.
FUZZ_ENV   := GOPROXY=off GOFLAGS="-mod=mod $(GOFLAGS)"
HOST_GOOS  := $(shell go env GOOS)
BATCH      ?=
BATCH_SEL  := $(if $(BATCH),select(.batch == $(BATCH)),.)

TARGETS := $(shell $(JQ) -r --arg os $(HOST_GOOS) '.targets[] | $(BATCH_SEL) | select((.language // "go") == "go") | select((.goos // $$os) == $$os) | .id' $(MANIFEST))
PY_TARGETS := $(shell $(JQ) -r '.targets[] | $(BATCH_SEL) | select(.language == "python") | .id' $(MANIFEST))
JS_TARGETS := $(shell $(JQ) -r '.targets[] | $(BATCH_SEL) | select(.language == "javascript") | .id' $(MANIFEST))
JAVA_TARGETS := $(shell $(JQ) -r '.targets[] | $(BATCH_SEL) | select(.language == "java") | .id' $(MANIFEST))

# Pinned jazzer release (rule S7: exact version + sha256; license
# Apache-2.0 VERIFIED AT THE TAG — docs/external-dependencies.md).
JAZZER_VERSION := 0.30.0
JAZZER_SHA256_macos := 6239e2b2b8d626c287fd8a50376315f00ef4310e3f29e96315cd6e60911563c8
JAZZER_SHA256_linux := 6eeaf0026d75599b07527d93b576593ce847cfca8b337a579971a5a9cdf792d0
JAZZER_ASSET_macos := jazzer-macos.tar.gz
JAZZER_ASSET_linux := jazzer-linux-x86-64.tar.gz
JAZZER_OS := $(if $(filter Darwin,$(shell uname -s)),macos,linux)
JAZZER_DIR := $(CLONES)/.jazzer-$(JAZZER_VERSION)
RS_TARGETS := $(shell $(JQ) -r '.targets[] | $(BATCH_SEL) | select(.language == "rust") | .id' $(MANIFEST))

.PHONY: list install build clone fuzz-all clean-harnesses \
	$(addprefix fuzz-,$(TARGETS)) $(addprefix fuzz-,$(PY_TARGETS)) \
	$(addprefix fuzz-,$(JS_TARGETS)) $(addprefix fuzz-,$(RS_TARGETS))

list:
	@$(JQ) -r '.targets[] | "\(.id)  (reach=\(.product_reach))\n" + (.harnesses[] | select(.fuzz!="") | "    \(.fuzz)  ->  \(.pkg)")' $(MANIFEST)

## install: copy harness files into their in-tree destinations.
install:
	@$(JQ) -r '.targets[] | (.clone_alias // .id) as $$dir | .harnesses[] | "\($$dir)|\(.file)|\(.dest)"' $(MANIFEST) | \
	while IFS='|' read -r dir src dest; do \
	  mkdir -p "$(CLONES)/$$dir/$$(dirname $$dest)"; \
	  cp "$(HARNESSES)/$$src" "$(CLONES)/$$dir/$$dest"; \
	  echo "  installed $$dir/$$dest"; \
	done

## build: compile every harness test binary (fast fail, no fuzz).
build: install
	@set -e; \
	$(JQ) -r --arg os $(HOST_GOOS) '.targets[] | $(BATCH_SEL) | select((.goos // $$os) == $$os) | select(.harnesses | length > 0) | "\(.id)|\(.clone_alias // .id)|\(.workdir // ".")|\(.harnesses | map(.pkg) | unique | join(" "))"' $(MANIFEST) | \
	while IFS='|' read -r id dir wd pkgs; do \
	  echo "== build $$id =="; \
	  ( cd "$(CLONES)/$$dir/$$wd" && go mod download 2>/dev/null; env $(FUZZ_ENV) go test -run '^$$' -count 1 $$pkgs ) || exit 1; \
	done
	@$(JQ) -r --arg os $(HOST_GOOS) '.targets[] | $(BATCH_SEL) | select((.goos // $$os) != $$os) | "  SKIP \(.id) (requires GOOS=\(.goos))"' $(MANIFEST)
	@echo "all host-compatible harnesses compile"

## fuzz-<id>: run every FuzzXxx in that target for FUZZTIME each.
$(addprefix fuzz-,$(TARGETS)): fuzz-%: install
	@$(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | .workdir as $$wd | .harnesses[] | select(.fuzz!="") | "\($$wd // ".")|\(.pkg)|\(.fuzz)"' $(MANIFEST) | \
	while IFS='|' read -r wd pkg fn; do \
	  echo "== $* :: $$fn ($$pkg) FUZZTIME=$(FUZZTIME) =="; \
	  ( cd "$(CLONES)/$*/$$wd" && go mod download 2>/dev/null; env $(FUZZ_ENV) go test -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) $$pkg ) || true; \
	done

fuzz-all: $(addprefix fuzz-,$(TARGETS))

## clone: (re)fetch all repos at pinned commits through the checkout
## service (traust repo checkout), symlinking clones/<id> at the printed
## workspace path. Idempotent.
clone:
	@$(JQ) -r '.targets[] | "\(.id)|\(.repo)|\(.commit)"' $(MANIFEST) | \
	while IFS='|' read -r id url sha; do \
	  test -e "$(CLONES)/$$id/.git" && { echo "  skip $$id (exists)"; continue; }; \
	  case "$$url" in \
	    *'$${FUZZ_MIRROR_BASE}'*) \
	      if [ -z "$$FUZZ_MIRROR_BASE" ]; then \
	        echo "  skip $$id (needs FUZZ_MIRROR_BASE: this target is mirrored, and the mirror host is deployment config, not a shipped constant)"; \
	        continue; \
	      fi; \
	      url=$$(printf '%s' "$$url" | sed "s#\$${FUZZ_MIRROR_BASE}#$$FUZZ_MIRROR_BASE#");; \
	  esac; \
	  case "$$url" in https://*) ;; *) echo "  refuse $$id (non-https url)"; continue;; esac; \
	  if [ "$$sha" = "HEAD" ]; then \
	    sha=$$(git ls-remote "$$url" HEAD | cut -f1); \
	  fi; \
	  work=$$(python3 -m traust.cli repo checkout "$$url" --ref "$$sha" --history 1 --writable); \
	  mkdir -p "$(CLONES)"; ln -sfn "$$work" "$(CLONES)/$$id"; \
	  echo "  checked out $$id"; \
	done

clean-harnesses:
	@$(JQ) -r '.targets[] | .id as $$id | .harnesses[] | "$(CLONES)/\($$id)/\(.dest)"' $(MANIFEST) | xargs -r rm -f

# ---- non-Go languages (C4) --------------------------------------------------

## fuzz-<id> for language=java: pinned jazzer release, FUZZTIME-bounded.
## Target repo must build with maven or gradle (harness .dest compiled
## alongside); harness class name comes from the manifest's .fuzz field.
$(JAZZER_DIR)/jazzer:
	@mkdir -p $(JAZZER_DIR)
	@curl -sSL -o $(JAZZER_DIR)/jazzer.tar.gz \
	  "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v$(JAZZER_VERSION)/$(JAZZER_ASSET_$(JAZZER_OS))"
	@echo "$(JAZZER_SHA256_$(JAZZER_OS))  $(JAZZER_DIR)/jazzer.tar.gz" | shasum -a 256 -c - \
	  || { echo "jazzer tarball sha256 MISMATCH — refusing"; rm -f $(JAZZER_DIR)/jazzer.tar.gz; exit 1; }
	@tar -xzf $(JAZZER_DIR)/jazzer.tar.gz -C $(JAZZER_DIR) && rm -f $(JAZZER_DIR)/jazzer.tar.gz
	@test -x $(JAZZER_DIR)/jazzer

$(addprefix fuzz-,$(JAVA_TARGETS)): fuzz-%: install $(JAZZER_DIR)/jazzer
	@dir=$$($(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | (.clone_alias // .id)' $(MANIFEST)); \
	wd=$$($(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | (.workdir // ".")' $(MANIFEST)); \
	( cd "$(CLONES)/$$dir/$$wd" && \
	  if [ -f pom.xml ]; then mvn -q -DskipTests package dependency:build-classpath -Dmdep.outputFile=.jazzer-cp.txt; \
	  elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then gradle -q assemble; find . -name '*.jar' -path '*/libs/*' | tr '\n' ':' > .jazzer-cp.txt; \
	  else echo "no maven/gradle build — cannot compile harness" >&2; exit 1; fi ); \
	$(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | .harnesses[] | select(.fuzz!="") | .fuzz' $(MANIFEST) | \
	while read -r cls; do \
	  echo "== $* :: $$cls (java/jazzer v$(JAZZER_VERSION)) FUZZTIME=$(FUZZTIME) =="; \
	  ( cd "$(CLONES)/$$dir/$$wd" && \
	    cp=$$(cat .jazzer-cp.txt 2>/dev/null):target/classes:build/classes/java/main; \
	    timeout $(FUZZTIME) $(abspath $(JAZZER_DIR))/jazzer --cp="$$cp" \
	      --target_class="$$cls" -rss_limit_mb=4096 ) || true; \
	done

## fuzz-<id> for language=python: atheris in a per-clone venv, FUZZTIME-bounded.
$(addprefix fuzz-,$(PY_TARGETS)): fuzz-%: install
	@dir=$$($(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | (.clone_alias // .id)' $(MANIFEST)); \
	test -x "$(CLONES)/$$dir/.fuzzvenv/bin/python" || python3 -m venv "$(CLONES)/$$dir/.fuzzvenv"; \
	"$(CLONES)/$$dir/.fuzzvenv/bin/pip" -q install "atheris==2.3.0"; \
	$(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | .harnesses[] | select(.fuzz!="") | .dest' $(MANIFEST) | \
	while read -r dest; do \
	  echo "== $* :: $$dest (python/atheris) FUZZTIME=$(FUZZTIME) =="; \
	  ( cd "$(CLONES)/$$dir" && timeout $(FUZZTIME) .fuzzvenv/bin/python "$$dest" -atheris_runs=0 ) || true; \
	done

## fuzz-<id> for language=javascript: Jazzer.js via npx, FUZZTIME-bounded.
$(addprefix fuzz-,$(JS_TARGETS)): fuzz-%: install
	@dir=$$($(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | (.clone_alias // .id)' $(MANIFEST)); \
	$(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | .harnesses[] | select(.fuzz!="") | .dest' $(MANIFEST) | \
	while read -r dest; do \
	  echo "== $* :: $$dest (javascript/Jazzer.js) FUZZTIME=$(FUZZTIME) =="; \
	  ( cd "$(CLONES)/$$dir" && npm install --no-save "@jazzer.js/core@2.1.0" 2>&1 | tail -1; \
	    timeout $(FUZZTIME) npx jazzer "$${dest%.js}" ) || true; \
	done

## fuzz-<id> for language=rust: cargo-fuzz (nightly), FUZZTIME-bounded.
$(addprefix fuzz-,$(RS_TARGETS)): fuzz-%: install
	@dir=$$($(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | (.clone_alias // .id)' $(MANIFEST)); \
	secs=$$(( $$(echo "$(FUZZTIME)" | sed 's/m/*60/;s/s//' | bc) )); \
	$(JQ) -r --arg id $* '.targets[] | select(.id==$$id) | .harnesses[] | select(.fuzz!="") | .fuzz' $(MANIFEST) | \
	while read -r fn; do \
	  echo "== $* :: $$fn (rust/cargo-fuzz) FUZZTIME=$(FUZZTIME) =="; \
	  ( cd "$(CLONES)/$$dir" && cargo +nightly fuzz run "$$fn" -- -max_total_time=$$secs ) || true; \
	done
