#!/bin/sh
# Publish the Conversion Worker from a Workers Builds image.
# Requires scripts/install-workers-toolchain.sh in the Build command.
# Does not touch SUB_HUB_ACCESS_TOKEN; set that Dashboard secret yourself.
#
#   sh scripts/workers-builds-deploy.sh
#   sh scripts/workers-builds-deploy.sh preview
#   sh scripts/workers-builds-deploy.sh worker
#   sh scripts/workers-builds-deploy.sh preview worker
#
# Default layout is all (Wasm + same-origin Console). `worker` skips
# Console assets and uses wrangler.worker.toml.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
worker_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
console_root=$(CDPATH= cd -- "$worker_root/../../apps/console" && pwd)
cd "$worker_root"

cargo_env="${CARGO_HOME:-$HOME/.cargo}/env"
if [ -f "$cargo_env" ]; then
  # shellcheck disable=SC1090
  . "$cargo_env"
fi

if ! command -v worker-build >/dev/null 2>&1; then
  printf '%s\n' "worker-build missing; run sh scripts/install-workers-toolchain.sh first" >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  printf '%s\n' "pnpm missing; set PNPM_VERSION on the Workers Builds project" >&2
  exit 1
fi

build_console() {
  (
    cd "$console_root"
    pnpm install --frozen-lockfile
    pnpm run build
  )
  if [ ! -f "$console_root/dist/index.html" ]; then
    printf '%s\n' "Console dist is missing at $console_root/dist" >&2
    exit 1
  fi
}

usage() {
  printf '%s\n' "usage: sh scripts/workers-builds-deploy.sh [deploy|preview] [all|worker]" >&2
  exit 1
}

mode=deploy
layout=all
for arg in "$@"; do
  case "$arg" in
    deploy|preview) mode=$arg ;;
    all|worker) layout=$arg ;;
    *) usage ;;
  esac
done

wrangler_args=""
if [ "$layout" = "worker" ]; then
  wrangler_args="--config wrangler.worker.toml"
else
  build_console
fi

case "$mode" in
  deploy)
    # shellcheck disable=SC2086
    exec npx wrangler deploy --keep-vars $wrangler_args
    ;;
  preview)
    # shellcheck disable=SC2086
    exec npx wrangler versions upload --keep-vars $wrangler_args
    ;;
  *)
    usage
    ;;
esac
