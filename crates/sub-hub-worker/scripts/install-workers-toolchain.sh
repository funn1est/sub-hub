#!/bin/sh
# Install the pinned Rust / Wasm toolchain for Cloudflare Workers Builds.
#
# The build image has Node but not Rust. This script does not deploy.
# Workers Builds sets CI=true; do not call `pnpm run deploy` from that image.
#
# Dashboard (Worker name `sub-hub`, root `crates/sub-hub-worker`):
#   Build:  sh scripts/install-workers-toolchain.sh
#   Deploy: sh scripts/workers-builds-deploy.sh
#
# Local Windows PowerShell is not a target. Use WSL/Git Bash, or stay on
# `pnpm run deploy` after a machine-local `cargo install worker-build`.

set -eu

RUST_TOOLCHAIN=1.97.1
WASM_TARGET=wasm32-unknown-unknown
WORKER_BUILD_VERSION=0.8.5
RUSTUP_URL=https://sh.rustup.rs

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
worker_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$worker_root"

cargo_env="${CARGO_HOME:-$HOME/.cargo}/env"

log() {
  printf '%s\n' "$*"
}

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

source_cargo_env() {
  if [ -f "$cargo_env" ]; then
    # shellcheck disable=SC1090
    . "$cargo_env"
  fi
}

install_rustup() {
  if command -v rustup >/dev/null 2>&1; then
    log "rustup already on PATH"
    return 0
  fi
  require_cmd curl
  log "installing rustup (${RUST_TOOLCHAIN}, ${WASM_TARGET})"
  curl --proto '=https' --tlsv1.2 -sSf "$RUSTUP_URL" | sh -s -- -y \
    --default-toolchain "$RUST_TOOLCHAIN" \
    --profile minimal \
    --target "$WASM_TARGET"
  source_cargo_env
  command -v rustup >/dev/null 2>&1 || fail "rustup finished but rustup is not on PATH"
}

ensure_toolchain() {
  rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --no-self-update
  rustup target add "$WASM_TARGET" --toolchain "$RUST_TOOLCHAIN"
}

worker_build_present() {
  cargo install --list | grep -q "^worker-build v${WORKER_BUILD_VERSION}:"
}

ensure_worker_build() {
  if worker_build_present; then
    log "worker-build ${WORKER_BUILD_VERSION} already installed"
    return 0
  fi
  log "installing worker-build ${WORKER_BUILD_VERSION}"
  cargo install worker-build --version "$WORKER_BUILD_VERSION" --locked
}

ensure_node_deps() {
  require_cmd pnpm
  pnpm install --frozen-lockfile
}

source_cargo_env
install_rustup
source_cargo_env
require_cmd rustup
require_cmd cargo
ensure_toolchain
ensure_worker_build
ensure_node_deps

log "toolchain ready: rust ${RUST_TOOLCHAIN}, ${WASM_TARGET}, worker-build ${WORKER_BUILD_VERSION}"
log "Workers Builds deploy command: sh scripts/workers-builds-deploy.sh"
