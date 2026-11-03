# Build stage: assemble the harness content
# This is a data-only OCI artifact — its layers are mounted as a volume by
# agent runtimes and nothing from a base OS is ever executed. We therefore
# build FROM scratch: no base image, no shell, no package surface to patch,
# and no digest to keep refreshing. The image contains only the COPY'd
# harness payload under /harness.
FROM scratch AS harness

# Harness semver, fed from version.args (generated from VERSION) via the
# Konflux build-args-file param; the release pipeline's {{ oci_version }}
# tag template reads org.opencontainers.image.version, so each released
# image is also tagged with this value.
ARG VERSION=0.0.0

# OCI artifact labels.
# vendor / url / release / distribution-scope are REQUIRED by the Konflux
# Enterprise Contract (labels.required_labels). They used to arrive for free
# as inherited ubi9-micro base labels; FROM scratch has no base, so a
# base-less image must declare them itself. Do not drop them.
LABEL name="traust" \
      org.opencontainers.image.version="${VERSION}" \
      summary="Traust — skills, scripts, and schemas for automated security assessments" \
      description="A data-only OCI artifact containing AI agent skills, prompt engineering, \
Python scripts, JSON schemas, and configuration for automated multi-framework security \
audits of Red Hat Hybrid Platforms source code. Mounted as a volume by agent runtimes." \
      version="${VERSION:-0.0.0}" \
      io.k8s.display-name="Traust" \
      io.k8s.description="AI agent harness for automated security assessments" \
      io.openshift.tags="ai,security,harness,skills,agents" \
      com.redhat.component="traust" \
      maintainer="Traust maintainers <traust@redhat.com>" \
      vendor="Red Hat, Inc." \
      url="https://catalog.redhat.com/en/search?searchType=containers" \
      release="1" \
      distribution-scope="public"

# Data-only artifact — no entrypoint, no pip install in-image.
# Consumers mount this tree (typically at /harness) and run Python from
# a separately installed stack: traust + traust-engine +
# traust-core, which pins traust-contracts + traust-ledger (pip/uv from pyproject.toml git pins).
#
# What lives where after the scripts/ → packages refactor:
#   harnessing/          skills, per-skill scripts — YES (payload)
#   packs/               the security pack: rule packs, SLA policy — YES (payload)
#   config/              shipped estate-neutral config + *.example.* templates — YES
#                        (deployment config is NOT here: mount it and set
#                        TRAUST_CONFIG_HOME — see config/README.md)
#   docs/                agent/human reference — YES
#   schema/              RETIRED — schemas ship in traust-contracts wheel
#   scripts/             RETIRED — CLIs in src/ + traust-engine; do not COPY
#   src/                 NOT in image — install the wheel on the host/CI runner
#
# Deployment-specific config (traust.yaml, model-registry, product map, the
# signing key) never ships in this image; it is mounted at $TRAUST_CONFIG_HOME.
# Tool pins, safe-exec profiles and the feeds registry ship with traust-core.

WORKDIR /harness

# Core skill definitions (the primary payload)
COPY harnessing/ ./harnessing/

# The security pack: rule packs, SLA policy, compliance catalogs (traust.paths reads them)
COPY packs/ ./packs/

# Shipped config (model-registry) + the traust.example.yaml template
COPY config/ ./config/
# Deployment config: mount at runtime, e.g. -v /path/to/deploy/config:/harness/deploy-config:ro
ENV TRAUST_CONFIG_HOME=/harness/deploy-config

# Documentation
COPY docs/ ./docs/

# Optional explicit skill-link helper (agents discover via harnessing/ + link_skills.sh)
COPY bin/ ./bin/

# Project metadata
COPY VERSION pyproject.toml requirements.txt ./
COPY LICENSE NOTICE ./
COPY LICENSES/ ./LICENSES/

# Certification tooling (ecosystem-cert-preflight-checks HasLicense) looks for
# license text at the absolute path /licenses, not under WORKDIR.
COPY LICENSES/ /licenses/

USER 1001

# No entrypoint — mount and pair with pip-installed sibling packages on the host
