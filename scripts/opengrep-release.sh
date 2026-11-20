# Reviewed official Opengrep release-asset metadata shared by local/CI installs
# and Containerfile.tools. A version bump must record upstream digests here:
# https://api.github.com/repos/opengrep/opengrep/releases/tags/v1.25.0
# Source this POSIX shell file; opengrep_release VERSION OS ARCH prints ASSET SHA256.
opengrep_release() {
  case "$1/$2/$3" in
    1.25.0/darwin/arm64)
      printf '%s %s\n' opengrep_osx_arm64 \
        3543fcabae9db2ae5bc974a3b75426353f0a3e369181b2157ef27f46867996c8 ;;
    1.25.0/darwin/amd64)
      printf '%s %s\n' opengrep_osx_x86 \
        fa2487b75527be1cc9ae4f9b0cb09a340454e7973c76785568285cbbcd977cb4 ;;
    1.25.0/linux/arm64)
      printf '%s %s\n' opengrep_manylinux_aarch64 \
        fd40124272d006082a5594b19aecee07b01dd50933d8add7a4fd5c557d2be5f6 ;;
    1.25.0/linux/amd64)
      printf '%s %s\n' opengrep_manylinux_x86 \
        9ac4aebb47ba3f7b0d8fc641ac8749cb6c2f253f616131a67d9631e00d4bea33 ;;
    *)
      echo "FATAL: no verified opengrep asset for v$1 on $2/$3" >&2
      return 1 ;;
  esac
}
