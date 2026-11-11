#!/bin/bash
# Negative fixture for the xtrace rule's file-level co-occurrence
# constraint: this script enables tracing but never mentions sensitive-value
# lexicon terms, so no fact is emitted.

# ok: traust-bash-data-exposure-xtrace
set -ex

# ok: traust-bash-data-exposure-xtrace
set -o xtrace

make build
cp artifact.tar.gz /output/
