#!/bin/bash

registry_logins() {
  # ruleid: traust-bash-data-exposure-cred-in-argv
  podman login -u="$RH_REGISTRY_USER" -p="$RH_REGISTRY_TOKEN" registry.redhat.io

  # ruleid: traust-bash-data-exposure-cred-in-argv
  docker login --password "$QUAY_TOKEN" -u bot quay.io

  # ok: traust-bash-data-exposure-cred-in-argv
  echo "$QUAY_TOKEN" | podman login --password-stdin -u bot quay.io

  # ok: traust-bash-data-exposure-cred-in-argv
  git login -p "$X"
}

# this script references credential-shaped identifiers (the login block
# above), so the xtrace rule's file-level co-occurrence constraint holds;
# the no-credential negative direction lives in data-exposure.nocred.sh
tracing() {
  # ruleid: traust-bash-data-exposure-xtrace
  set -exv

  # ruleid: traust-bash-data-exposure-xtrace
  set -x

  # ruleid: traust-bash-data-exposure-xtrace
  set -o xtrace

  # ok: traust-bash-data-exposure-xtrace
  set -euo pipefail
}
