#!/usr/bin/env bash
# Build, install and run Bosun from a checkout.
#
#   scripts/bosun.sh deps                  install the Linux packages the desktop app needs (uses sudo)
#   scripts/bosun.sh build [engine|desktop|all]   build the web UI and the binaries (default: engine)
#   scripts/bosun.sh run [engine|desktop] [-- ARGS]   build if needed, then run
#   scripts/bosun.sh install [PREFIX]      build the engine and copy it to PREFIX/bin (default ~/.local)
#   scripts/bosun.sh container [TAG]       build the container image (default tag: bosun:local)
#   scripts/bosun.sh up | down             build and start / stop the container with compose.example.yaml
#   scripts/bosun.sh check                 run the same checks CI runs (clippy, tests, web check)
#
# The engine needs Rust (rustup) and Node. The desktop app also needs the webview libraries (see `deps`).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found. $2"; }

web() {
  need node "Install Node 20 or newer (https://nodejs.org)."
  need npm "Install npm with Node."
  if [ ! -d web/node_modules ]; then npm --prefix web ci --no-audit --no-fund; fi
  npm --prefix web run build
}

deps() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libssl-dev libwebkit2gtk-4.1-dev libgtk-3-dev \
      libayatana-appindicator3-dev librsvg2-dev
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y gcc pkgconf-pkg-config openssl-devel webkit2gtk4.1-devel gtk3-devel \
      libappindicator-gtk3-devel librsvg2-devel
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed base-devel webkit2gtk-4.1 gtk3 libayatana-appindicator librsvg
  else
    die "unknown package manager; install the WebKitGTK 4.1, GTK 3, appindicator and librsvg dev packages yourself."
  fi
}

build() {
  need cargo "Install Rust from https://rustup.rs (the toolchain version is pinned in rust-toolchain.toml)."
  case "${1:-engine}" in
    engine)  web; cargo build --release -p bosun ;;
    desktop) web; cargo build --release -p bosun-desktop ;;
    all)     web; cargo build --release -p bosun; cargo build --release -p bosun-desktop ;;
    *) die "build: expected engine, desktop or all" ;;
  esac
}

run() {
  local what="${1:-engine}"; shift || true
  [ "${1:-}" = "--" ] && shift
  case "$what" in
    engine)  build engine;  exec ./target/release/bosun serve "$@" ;;
    desktop) build desktop; exec ./target/release/bosun-desktop "$@" ;;
    *) die "run: expected engine or desktop" ;;
  esac
}

install_() {
  local prefix="${1:-$HOME/.local}"
  build engine
  install -D -m 0755 target/release/bosun "$prefix/bin/bosun"
  echo "installed $prefix/bin/bosun"
  case ":$PATH:" in *":$prefix/bin:"*) ;; *) echo "note: $prefix/bin is not on your PATH" ;; esac
}

container() {
  need docker "Install Docker (or Podman with a docker alias)."
  docker build -t "${1:-bosun:local}" .
}

check() {
  need cargo "Install Rust from https://rustup.rs."
  cargo clippy --all-targets -- -D warnings
  cargo test
  need npm "Install Node."
  [ -d web/node_modules ] || npm --prefix web ci --no-audit --no-fund
  npm --prefix web run check
}

cmd="${1:-help}"; shift || true
case "$cmd" in
  deps) deps ;;
  build) build "$@" ;;
  run) run "$@" ;;
  install) install_ "$@" ;;
  container) container "$@" ;;
  up) need docker "Install Docker."; docker compose -f compose.example.yaml up -d --build
      echo "setup link: docker compose -f compose.example.yaml logs bosun" ;;
  down) need docker "Install Docker."; docker compose -f compose.example.yaml down ;;
  check) check ;;
  help|-h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '$cmd' (try: scripts/bosun.sh help)" ;;
esac
