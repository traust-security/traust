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
