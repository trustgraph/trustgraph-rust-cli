#!/bin/sh
# Trust Graph installer: puts the `trust` CLI on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/trustgraph/trustgraph-rust-cli/refs/heads/master/install.sh | sh
#
# This is a stable entry point that defers to the installer `dist` attaches to
# each GitHub release (trustgraph-cli-installer.sh, see doc/releasing.md). That
# installer picks the right prebuilt binary (glibc or musl on Linux, Intel or
# Apple silicon on macOS), checks its SHA-256 and adds it to your PATH. When
# there is no release yet, or none for your platform, this builds from source
# with cargo instead.
#
# Arguments are passed to the release installer, for example:
#   curl -fsSL .../install.sh | sh -s -- --no-modify-path
#
# Environment:
#   TRUST_INSTALL_DIR  where to put the binary (default: $XDG_BIN_HOME or ~/.local/bin)
#   TRUST_VERSION      release tag to install, e.g. v0.2.0 (default: latest)
#   TRUST_FROM_SOURCE  set to 1 to always build from source

set -eu

REPO="trustgraph/trustgraph-rust-cli"
VERSION="${TRUST_VERSION:-latest}"

say() { printf 'trust-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }

install_release() {
  [ "${TRUST_FROM_SOURCE:-0}" = 1 ] && return 1
  has curl || return 1
  case "$(uname -s)" in Linux | Darwin) ;; *) return 1 ;; esac
  if [ "$VERSION" = latest ]; then
    url="https://github.com/$REPO/releases/latest/download/trustgraph-cli-installer.sh"
  else
    url="https://github.com/$REPO/releases/download/$VERSION/trustgraph-cli-installer.sh"
  fi
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "$url" -o "$tmp/installer.sh" 2>/dev/null || return 1
  say "running the release installer from $url"
  if [ -n "${TRUST_INSTALL_DIR:-}" ]; then
    TRUSTGRAPH_CLI_INSTALL_DIR="$TRUST_INSTALL_DIR" sh "$tmp/installer.sh" "$@"
  else
    sh "$tmp/installer.sh" "$@"
  fi
}

install_source() {
  has cargo || die "no prebuilt binary for this platform and no cargo found.
  Install Rust (https://rustup.rs) and run this again."
  dir="${TRUST_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
  say "no prebuilt binary; building from source with cargo (takes a minute)"
  ref="--branch master"
  [ "$VERSION" = latest ] || ref="--tag $VERSION"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  # shellcheck disable=SC2086 # $ref is two words on purpose
  cargo install --locked --git "https://github.com/$REPO" $ref \
    --root "$tmp" trustgraph-cli
  mkdir -p "$dir"
  install -m 755 "$tmp/bin/trust" "$dir/trust"
  say "installed $dir/trust"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "add $dir to your PATH: export PATH=\"$dir:\$PATH\"" ;;
  esac
}

main() {
  if install_release "$@"; then :; else install_source; fi
  say "next: trust key new"
}

# Everything runs from here, so a truncated download executes nothing.
main "$@"
