#!/bin/sh
# Trust Graph installer: puts the `trust` CLI on your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/trustgraph/trustgraph-rust-cli/refs/heads/master/install.sh | sh
#
# Sketch: uses a prebuilt binary from the latest GitHub release when one exists
# (none yet, see doc/plan), otherwise builds from source with cargo.
#
# Environment:
#   TRUST_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
#   TRUST_VERSION      release tag to install (default: latest)

set -eu

REPO="trustgraph/trustgraph-rust-cli"
INSTALL_DIR="${TRUST_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${TRUST_VERSION:-latest}"

say() { printf 'trust-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }

target() {
  os=$(uname -s) arch=$(uname -m)
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=aarch64 ;;
    *) return 1 ;;
  esac
  case "$os" in
    Linux) echo "$arch-unknown-linux-gnu" ;;
    Darwin) echo "$arch-apple-darwin" ;;
    *) return 1 ;;
  esac
}

install_release() {
  has curl && has tar || return 1
  t=$(target) || return 1
  if [ "$VERSION" = latest ]; then
    url="https://github.com/$REPO/releases/latest/download/trustgraph-cli-$t.tar.xz"
  else
    url="https://github.com/$REPO/releases/download/$VERSION/trustgraph-cli-$t.tar.xz"
  fi
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "$url" -o "$tmp/trust.tar.xz" 2>/dev/null || return 1
  say "downloaded $url"
  tar -xJf "$tmp/trust.tar.xz" -C "$tmp"
  bin=$(find "$tmp" -type f -name trust | head -n 1)
  [ -n "$bin" ] || die "release archive has no 'trust' binary"
  mkdir -p "$INSTALL_DIR"
  install -m 755 "$bin" "$INSTALL_DIR/trust"
}

install_source() {
  has cargo || die "no prebuilt binary for this platform and no cargo found.
  Install Rust (https://rustup.rs) and run this again."
  say "no prebuilt binary; building from source with cargo (takes a minute)"
  ref="--branch master"
  [ "$VERSION" = latest ] || ref="--tag $VERSION"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  # shellcheck disable=SC2086 # $ref is two words on purpose
  cargo install --locked --git "https://github.com/$REPO" $ref \
    --root "$tmp" trustgraph-cli
  mkdir -p "$INSTALL_DIR"
  install -m 755 "$tmp/bin/trust" "$INSTALL_DIR/trust"
}

main() {
  if install_release; then :; else install_source; fi
  say "installed $INSTALL_DIR/trust"
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "add $INSTALL_DIR to your PATH: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac
  say "next: trust key new"
}

# Everything runs from here, so a truncated download executes nothing.
main "$@"
