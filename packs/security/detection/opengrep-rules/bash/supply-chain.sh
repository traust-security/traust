#!/bin/bash

install_tools() {
  # ruleid: traust-bash-supply-chain-curl-pipe-shell
  curl -sSfL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" | sh -s -- -b "$DEST"

  # ruleid: traust-bash-supply-chain-curl-pipe-shell
  wget -qO- https://get.example.io | bash

  # ok: traust-bash-supply-chain-curl-pipe-shell
  curl -sSfL -o /tmp/install.sh "https://raw.githubusercontent.com/anchore/syft/main/install.sh"

  # ok: traust-bash-supply-chain-curl-pipe-shell
  curl -s https://api.example.com/status | jq .state

  # Fixed download/verify/execute flow. The digest must be independently
  # trusted; downloading an untrusted checksum alongside the script is not enough.
  # ok: traust-bash-supply-chain-curl-pipe-shell
  curl -sSfL -o "$INSTALLER" "https://get.example.io/v1.2.3/install.sh" &&
    printf '%s  %s\n' "$PINNED_INSTALLER_SHA256" "$INSTALLER" | sha256sum -c - &&
    sh "$INSTALLER"
}

# --- traust-bash-regression-codecov-uploader-latest ---
codecov_download() {
	# ruleid: traust-bash-regression-codecov-uploader-latest
	export CODECOV_BIN="https://uploader.codecov.io/latest/linux/codecov"
	# ruleid: traust-bash-regression-codecov-uploader-latest
	curl -Os "https://uploader.codecov.io/latest/macos/codecov"
	# ok: traust-bash-regression-codecov-uploader-latest
	curl -Os "https://uploader.codecov.io/v0.7.3/linux/codecov" && sha256sum -c codecov.SHA256SUM
}
