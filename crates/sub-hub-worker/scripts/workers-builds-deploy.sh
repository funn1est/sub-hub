#!/bin/sh
# Publish the Conversion Worker from a Workers Builds image.
# Requires scripts/install-workers-toolchain.sh in the Build command.
# Does not touch SUB_HUB_ACCESS_TOKEN; after the first successful build,
# add it under Settings → Runtime variables and secrets (+ Add variable,
# Secret checked) if you want /sub/<token>.
#
#   sh scripts/workers-builds-deploy.sh
#   sh scripts/workers-builds-deploy.sh preview
#   sh scripts/workers-builds-deploy.sh worker
#   sh scripts/workers-builds-deploy.sh preview worker
#
# Default layout is all (Wasm + same-origin Console). That path publishes
# the repository-root wrangler.toml so the Deploy-to-Cloudflare wizard
# name edits apply. `worker` skips Console assets and uses
# wrangler.worker.toml.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
worker_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
repo_root=$(CDPATH= cd -- "$worker_root/../.." && pwd)
console_root=$(CDPATH= cd -- "$repo_root/apps/console" && pwd)
wrangler_bin="$worker_root/node_modules/.bin/wrangler"

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

if [ ! -x "$wrangler_bin" ]; then
  printf '%s\n' "wrangler missing; run sh scripts/install-workers-toolchain.sh first" >&2
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

if [ "$layout" = "worker" ]; then
  wrangler_config="$worker_root/wrangler.worker.toml"
  wrangler_cwd="$worker_root"
else
  build_console
  if [ -f "$repo_root/wrangler.toml" ]; then
    wrangler_config="$repo_root/wrangler.toml"
    wrangler_cwd="$repo_root"
  else
    wrangler_config="$worker_root/wrangler.toml"
    wrangler_cwd="$worker_root"
  fi
fi

cd "$wrangler_cwd"

case "$mode" in
  deploy)
    exec "$wrangler_bin" deploy --keep-vars --config "$wrangler_config"
    ;;
  preview)
    exec "$wrangler_bin" versions upload --keep-vars --config "$wrangler_config"
    ;;
  *)
    usage
    ;;
esac
