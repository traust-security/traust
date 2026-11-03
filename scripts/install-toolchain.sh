#!/usr/bin/env bash
# install-toolchain.sh — install external scanner tools for a harness profile.
#
# Usage:
#   ./scripts/install-toolchain.sh secure-code-audit
#   ./scripts/install-toolchain.sh secure-container-audit
#   ./scripts/install-toolchain.sh local-ops
#   ./scripts/install-toolchain.sh --all
#
# This script installs the actual binaries. It is the "one command" the
# opinionated toolchain stance promises. After running, `toolchain doctor`
# should pass.
#
# Every binary comes straight from its upstream project's GitHub release,
# at the version pinned in the external-tools.yaml traust-core ships (the single
# source of truth — the same pins Containerfile.tools consumes). No third-party
# package manager or package index sits in between. Where upstream publishes
# a checksum file, the download is verified against it before install.
#
# Requires: bash, curl, tar. Uses brew (macOS) or dnf/apt (Linux) only for
# the tools upstream does not ship as a standalone binary (skopeo, yara,
# joern) and pipx/pip for pip-audit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# The pins ship with the installed traust-core package (`uv sync` first).
PY="$REPO_ROOT/.venv/bin/python"; [[ -x "$PY" ]] || PY=python3
TOOLS_YAML="$("$PY" -c 'from traust_core.v1.context.config import SHIPPED_EXTERNAL_TOOLS as p; print(p)')" || {
  echo "FATAL: traust-core not importable — run \`uv sync\` in the traust checkout first" >&2
  exit 1
}

# Where directly-downloaded binaries land. Must be on PATH.
BIN_DIR="${HARNESS_BIN_DIR:-$HOME/.local/bin}"

# Tool → profile mapping (mirrors external-tools.yaml consumers).
# osv-scanner is deliberately absent: OSV is queried through its API, and an
# air-gapped deployment installs osv-scanner and its offline database itself
# (docs/setup.md "Air-gapped OSV scanning"; owner decision 2026-10-20).
#
# A newline-delimited "profile:tools" table rather than `declare -A`, because
# macOS ships bash 3.2 and associative arrays are bash 4+. Under 3.2 the old
# form did not merely degrade — `[secure-code-audit]=...` was parsed as an
# arithmetic index, so `secure` evaluated as an unset variable and `set -u`
# aborted the script before it did anything. Single source of truth: both
# helpers below read this one string.
PROFILE_TABLE='
secure-code-audit:opengrep gitleaks syft grype govulncheck pip-audit
secure-container-audit:syft grype cosign skopeo yara
secure-rpm-audit:syft grype yara govulncheck joern
vuln-scan:opengrep gitleaks
dependency-watch:gitleaks
impact-analysis:joern
triage:govulncheck
ledger-signing:cosign
local-ops:syft
'

# All profile names, space-separated.
profile_names() {
  local line names=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    names="$names ${line%%:*}"
  done <<EOF
$PROFILE_TABLE
EOF
  echo "${names# }"
}

# Tools for profile $1 on stdout; non-zero and no output when unknown.
profile_tools() {
  local line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ "${line%%:*}" = "$1" ]; then
      printf '%s\n' "${line#*:}"
      return 0
    fi
  done <<EOF
$PROFILE_TABLE
EOF
  return 1
}

# Tools installed by direct download from their upstream GitHub release.
DIRECT_TOOLS="opengrep gitleaks syft grype cosign govulncheck"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BOLD}==> $1${NC}"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
warn()  { echo -e "  ${YELLOW}!${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; }

usage() {
  echo "Usage: $0 <profile> [--dry-run]"
  echo "       $0 --all [--dry-run]"
  echo ""
  echo "Profiles: $(profile_names)"
  exit 1
}

# --- Detect platform ---
detect_platform() {
  case "$(uname -s)" in
    Darwin) PLATFORM="macos"; OS="darwin" ;;
    Linux)  PLATFORM="linux"; OS="linux" ;;
    *)      echo "Unsupported platform: $(uname -s)"; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)             echo "Unsupported arch: $(uname -m)"; exit 1 ;;
  esac
}

# --- Version pins (single source of truth: traust-core's shipped external-tools.yaml) ---

# Print the `expected:` pin for tool $1. Fails loudly when missing so a
# renamed or dropped manifest entry cannot silently install "latest".
pin_for() {
  local v
  v="$(awk -v name="$1" '
    $1 == "-" && $2 == "name:" { cur = $3 }
    cur == name && $1 == "expected:" { gsub(/"/, "", $2); print $2; exit }
  ' "$TOOLS_YAML")"
  if [[ -z "$v" ]]; then
    echo "FATAL: no 'expected' pin for $1 in $TOOLS_YAML" >&2
    return 1
  fi
  printf '%s\n' "$v"
}

# --- Download helpers ---

# fetch URL DEST — TLS-only, follow redirects, fail on HTTP errors.
fetch() {
  curl -sSfL --proto '=https' --tlsv1.2 -o "$2" "$1"
}

sha256_of() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# verify_checksum FILE CHECKSUMS_URL ASSET_NAME — fetch the upstream checksum
# file and compare. Downloaded, verified, THEN installed (gate S7).
verify_checksum() {
  local file="$1" url="$2" asset="$3" sums expected actual
  sums="$(mktemp)"
  fetch "$url" "$sums"
  expected="$(awk -v a="$asset" '$2 == a || $2 == "*" a {print $1; exit}' "$sums")"
  rm -f "$sums"
  if [[ -z "$expected" ]]; then
    echo "FATAL: $asset not listed in $url" >&2
    return 1
  fi
  actual="$(sha256_of "$file")"
  if [[ "$actual" != "$expected" ]]; then
    echo "FATAL: checksum mismatch for $asset" >&2
    echo "  expected $expected" >&2
    echo "  got      $actual" >&2
    return 1
  fi
}

install_bin() {
  mkdir -p "$BIN_DIR"
  install -m 0755 "$1" "$BIN_DIR/$2"
}

# --- Installers per tool (direct upstream downloads) ---

install_opengrep() {
  if command -v opengrep &>/dev/null; then ok "opengrep already installed"; return; fi
  local v asset tmp
  v="$(pin_for opengrep)"
  info "Installing opengrep v$v..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install opengrep v$v"; return; fi
  case "$OS/$ARCH" in
    darwin/arm64) asset="opengrep_osx_arm64" ;;
    darwin/amd64) asset="opengrep_osx_x86" ;;
    linux/arm64)  asset="opengrep_manylinux_aarch64" ;;
    linux/amd64)  asset="opengrep_manylinux_x86" ;;
  esac
  tmp="$(mktemp)"
  # Upstream publishes no checksum file for opengrep; the pinned version and
  # TLS-only fetch from the release URL are the guarantee here.
  fetch "https://github.com/opengrep/opengrep/releases/download/v${v}/${asset}" "$tmp"
  install_bin "$tmp" opengrep
  rm -f "$tmp"
  ok "opengrep installed to $BIN_DIR"
}

install_gitleaks() {
  if command -v gitleaks &>/dev/null; then ok "gitleaks already installed"; return; fi
  local v arch asset base tmpd
  v="$(pin_for gitleaks)"
  info "Installing gitleaks v$v..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install gitleaks v$v"; return; fi
  arch="$ARCH"; [[ "$ARCH" == "amd64" ]] && arch="x64"
  asset="gitleaks_${v}_${OS}_${arch}.tar.gz"
  base="https://github.com/gitleaks/gitleaks/releases/download/v${v}"
  tmpd="$(mktemp -d)"
  fetch "$base/$asset" "$tmpd/$asset"
  verify_checksum "$tmpd/$asset" "$base/gitleaks_${v}_checksums.txt" "$asset"
  tar -C "$tmpd" -xzf "$tmpd/$asset" gitleaks
  install_bin "$tmpd/gitleaks" gitleaks
  rm -rf "$tmpd"
  ok "gitleaks installed to $BIN_DIR"
}

# Anchore tools share one release layout.
install_anchore() {
  local tool="$1" v asset base tmpd
  if command -v "$tool" &>/dev/null; then ok "$tool already installed"; return; fi
  v="$(pin_for "$tool")"
  info "Installing $tool v$v..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install $tool v$v"; return; fi
  asset="${tool}_${v}_${OS}_${ARCH}.tar.gz"
  base="https://github.com/anchore/${tool}/releases/download/v${v}"
  tmpd="$(mktemp -d)"
  fetch "$base/$asset" "$tmpd/$asset"
  verify_checksum "$tmpd/$asset" "$base/${tool}_${v}_checksums.txt" "$asset"
  tar -C "$tmpd" -xzf "$tmpd/$asset" "$tool"
  install_bin "$tmpd/$tool" "$tool"
  rm -rf "$tmpd"
  ok "$tool installed to $BIN_DIR"
}

install_cosign() {
  if command -v cosign &>/dev/null; then ok "cosign already installed"; return; fi
  local v asset base tmp
  v="$(pin_for cosign)"
  info "Installing cosign v$v..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install cosign v$v"; return; fi
  asset="cosign-${OS}-${ARCH}"
  base="https://github.com/sigstore/cosign/releases/download/v${v}"
  tmp="$(mktemp)"
  fetch "$base/$asset" "$tmp"
  verify_checksum "$tmp" "$base/cosign_checksums.txt" "$asset"
  install_bin "$tmp" cosign
  rm -f "$tmp"
  ok "cosign installed to $BIN_DIR"
}

install_govulncheck() {
  if command -v govulncheck &>/dev/null; then ok "govulncheck already installed"; return; fi
  local v
  v="$(pin_for govulncheck)"
  info "Installing govulncheck v$v (go install, pinned module)"
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install govulncheck v$v"; return; fi
  if ! command -v go &>/dev/null; then
    fail "govulncheck is built with 'go install' and needs a Go toolchain — https://go.dev/dl/"
    return 1
  fi
  mkdir -p "$BIN_DIR"
  GOBIN="$BIN_DIR" go install "golang.org/x/vuln/cmd/govulncheck@v${v}"
  ok "govulncheck installed to $BIN_DIR"
}

# --- Installers per tool (no upstream standalone binary) ---

install_skopeo() {
  if command -v skopeo &>/dev/null; then ok "skopeo already installed"; return; fi
  info "Installing skopeo..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install skopeo"; return; fi
  if [[ "$PLATFORM" == "macos" ]]; then
    brew install skopeo
  else
    sudo dnf install -y skopeo 2>/dev/null || sudo apt-get install -y skopeo 2>/dev/null || {
      fail "Could not install skopeo — install manually: https://github.com/containers/skopeo/blob/main/install.md"
      return 1
    }
  fi
  ok "skopeo installed"
}

install_yara() {
  if command -v yara &>/dev/null; then ok "yara already installed"; return; fi
  info "Installing yara..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install yara"; return; fi
  if [[ "$PLATFORM" == "macos" ]]; then
    brew install yara
  else
    sudo dnf install -y yara 2>/dev/null || sudo apt-get install -y yara 2>/dev/null || {
      fail "Could not install yara — install manually: https://github.com/VirusTotal/yara/releases"
      return 1
    }
  fi
  ok "yara installed"
}

install_pip_audit() {
  if command -v pip-audit &>/dev/null; then ok "pip-audit already installed"; return; fi
  local v
  v="$(pin_for pip-audit)"
  info "Installing pip-audit v$v..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install pip-audit v$v"; return; fi
  if command -v pipx &>/dev/null; then
    pipx install "pip-audit==$v"
  elif command -v pip &>/dev/null; then
    pip install --user "pip-audit==$v"
  else
    fail "Neither pipx nor pip found — install pipx first: brew install pipx"
    return 1
  fi
  ok "pip-audit installed"
}

install_joern() {
  if command -v joern &>/dev/null; then ok "joern already installed"; return; fi
  info "Installing joern..."
  if [[ "$DRY_RUN" == "true" ]]; then warn "dry-run: would install joern"; return; fi
  if [[ "$PLATFORM" == "macos" ]]; then
    brew install joern
  else
    fail "joern requires manual install on Linux — https://github.com/joernio/joern/releases (needs Java 11+)"
    return 1
  fi
  ok "joern installed"
}

install_tool() {
  case "$1" in
    opengrep)    install_opengrep ;;
    gitleaks)    install_gitleaks ;;
    syft|grype)  install_anchore "$1" ;;
    cosign)      install_cosign ;;
    govulncheck) install_govulncheck ;;
    skopeo)      install_skopeo ;;
    yara)        install_yara ;;
    pip-audit)   install_pip_audit ;;
    joern)       install_joern ;;
    # checkov handled separately (pinned in traust-core's models/cloud_config.py)
    *)           ;;
  esac
}

populate_dbs() {
  local tools="$1"
  local db_tools=""
  for tool in $tools; do
    if [[ "$tool" == "grype" ]]; then
      if command -v "$tool" &>/dev/null; then
        db_tools="$db_tools $tool"
      fi
    fi
  done
  if [[ -z "$db_tools" ]]; then return; fi

  info "Populating vulnerability databases:$db_tools"
  if [[ "$DRY_RUN" == "true" ]]; then
    warn "dry-run: would populate DBs"
    return
  fi
  for tool in $db_tools; do
    case "$tool" in
      grype)
        grype db update && ok "grype DB updated" || warn "grype DB update failed"
        ;;
    esac
  done
}

# --- Main ---

DRY_RUN="false"
PROFILE=""

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN="true" ;;
    --all)     PROFILE="__all__" ;;
    --help|-h) usage ;;
    -*)        echo "Unknown flag: $arg"; usage ;;
    *)         PROFILE="$arg" ;;
  esac
done

[[ -z "$PROFILE" ]] && usage

detect_platform
echo ""
echo -e "${BOLD}Harness toolchain installer${NC}"
echo -e "Platform: $PLATFORM/$ARCH"
echo -e "Pins:     $TOOLS_YAML"
echo -e "Bin dir:  $BIN_DIR"
echo ""

if [[ "$PROFILE" == "__all__" ]]; then
  # Deduplicate across all profiles
  all_tools=""
  for p in $(profile_names); do
    all_tools="$all_tools $(profile_tools "$p")"
  done
  tools=$(echo "$all_tools" | tr ' ' '\n' | sort -u | tr '\n' ' ')
  info "Installing ALL tools: $tools"
else
  tools="$(profile_tools "$PROFILE" || true)"
  if [[ -z "$tools" ]]; then
    echo "Unknown profile: $PROFILE"
    echo "Available: $(profile_names)"
    exit 1
  fi
  info "Profile: $PROFILE"
  info "Tools: $tools"
fi

echo ""

# Step 1: install every tool in the profile
export PATH="$BIN_DIR:$PATH"
for tool in $tools; do
  install_tool "$tool"
done

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add it to your shell profile" ;;
esac

# Step 2: populate DBs
echo ""
populate_dbs "$tools"

# Step 3: verify
echo ""
info "Verifying..."
