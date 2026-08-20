#!/bin/sh
# Publish the Conversion Worker from a Workers Builds image.
# Requires scripts/install-workers-toolchain.sh in the Build command.
# Does not touch SUB_HUB_ACCESS_TOKEN; set that Dashboard secret yourself.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
worker_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
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

mode=${1:-deploy}
case "$mode" in
  deploy)
    exec npx wrangler deploy --keep-vars
    ;;
  preview)
    exec npx wrangler versions upload --keep-vars
    ;;
  *)
    printf '%s\n' "usage: sh scripts/workers-builds-deploy.sh [deploy|preview]" >&2
    exit 1
    ;;
esac
