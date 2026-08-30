# Sub Hub Cloudflare Worker

This crate hosts Sub Hub on Cloudflare Workers. One origin serves the
Conversion Service and the Web Console. The native service with
`SUB_HUB_CONSOLE_ROOT` is the same shape.

This repository does not operate a public instance. Deploy your own Worker if
you want a public URL.

## Runtime boundary

The Cloudflare remote adapter accepts only HTTPS destinations on port 443. An
initial URL using another port receives `400`; a redirect to another port
receives `502`. This restriction is specific to the Cloudflare adapter and does
not apply to the native host.

The hostname of the inbound request is always treated as a self-target. Remote
subscription and config URLs must not point at that host.

## Access token

`SUB_HUB_ACCESS_TOKEN` is a Cloudflare **secret** (never a `[vars]` value or a
committed `.dev.vars` file). The Deploy-to-Cloudflare prompt reads
repository-root `.dev.vars.example`; the copy in this directory stays empty
and in sync. Do not copy either file to `.dev.vars`. The blob is a comma- or
newline-separated list of at most eight equivalent tokens. Each token is 1–128 bytes from
`A–Z a–z 0–9 - . _ ~`. Any configured token authorizes `GET`/`HEAD /sub/<token>`.
`GET /sub` then returns `401 Unauthorized!`. `GET /version` stays public.
If the secret is **unset**, Worker `GET /sub` stays anonymous. That is
host behavior, not a packaging leftover. Native still refuses a
non-loopback bind with an empty token list. `pnpm run deploy` generates a
token when `wrangler secret list` shows the name absent; Dashboard Git /
Workers Builds does **not** put the secret — set it after the first
successful build.

Cloudflare cannot show the value after save. Keep the full list in a password
manager or an uncommitted file. The Dashboard field can only **replace** that
blob; it is not a viewer. Do not create a `SUB_HUB_ACCESS_TOKEN` **var** — a var
shadows the secret.

`pnpm run deploy` will:

- put the list you pass with `--tokens-file` or `--from-env`;
- leave an existing secret unchanged;
- or, when `wrangler secret list` proves the name is absent, generate one
  32-character hex token, put it with the same deploy, and print it once.

It never treats an ambient `SUB_HUB_ACCESS_TOKEN` as a put. If it cannot tell
whether the secret exists, it aborts instead of generating.

```sh
pnpm run deploy -- --tokens-file tokens.txt
pnpm run deploy -- --replace
```

A present-but-empty or malformed secret makes every request return `500`.

Do not log complete request URLs. Query strings commonly contain credentials.
Wrangler enables Workers Logs with `invocation_logs = false` so Fetch
invocation messages (method + URL) are not stored. Invalid-binding errors
still go to `console.error`.

## Prerequisites

- A Cloudflare account
- [mise](https://mise.jdx.dev/) so this repository can select Rust 1.97.1,
  `wasm32-unknown-unknown`, `rustfmt`, Clippy, Node.js 24.19.0, and pnpm
  11.22.0 from `mise.toml`
- `worker-build` 0.8.5

Install the pinned Worker build tool once per machine:

```sh
cargo install worker-build --version 0.8.5 --locked
```

## Self-serve deploy

From this directory:

```sh
pnpm install --frozen-lockfile
pnpm exec wrangler login
pnpm run build
pnpm run test:host
pnpm run deploy
```

`pnpm run deploy` is layout `all`: it builds `apps/console`, ensures the
access-token secret, and publishes **one** Worker (Wasm + Console assets).
Open the printed `*.workers.dev` URL: that is the Console. Same-origin
`/version` fills the Conversion Service origin. Paste the token into the
page. Save any generated token immediately; Cloudflare cannot show it
again.

Three layouts:

| Command | What is published |
| --- | --- |
| `pnpm run deploy` | Conversion + Console, same origin (default) |
| `pnpm run deploy:worker` | Conversion only (`wrangler.worker.toml`) |
| `pnpm run deploy:console` | Console only (`apps/console`, Worker `sub-hub-console`) |

`--layout all|worker|console` is the same switch. Conversion-only plus
a separate Console needs `SUB_HUB_CORS_ORIGINS` on Conversion:

```sh
pnpm run deploy:console
pnpm run deploy:worker -- --cors-origin https://sub-hub-console.<subdomain>.workers.dev
```

If the account already has a Worker named `sub-hub`, pass `--worker-name` or
set `CLOUDFLARE_WORKER_NAME` so the deploy does not collide. Console-only
uses `--console-name` / `CLOUDFLARE_CONSOLE_NAME`. Do not commit a local
`name` rename, an `account_id`, API tokens, or a `.dev.vars` file that
holds real values.

### Cloudflare Free

Layout `all` fits the [Workers Free](https://developers.cloudflare.com/workers/platform/limits/)
plan: the compressed Worker script is under the 3 MB gzip limit (this
repository's Wasm gzip is well under 1 MB); `pnpm run test:host` after
`worker-build --release` fails if gzip reaches 3 MiB, and CI cannot skip
that check. Console files are Workers Static Assets (Free allows 20,000
files, 25 MiB each) and do **not** count toward that 3 MB. Static asset
requests are [free and
unlimited](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/).
`/version` and `/sub` invoke the script (`run_worker_first`) and count
toward the Free 100,000 requests/day and 10 ms CPU/request. Two Workers
(console-only + conversion-only) also fit Free (100 Workers/account).

A typical ACL4SSR `/sub` may spend most of its wall time in `fetch`
(not billed as CPU) and then spend Wasm CPU on Keep-pass. Free is 10 ms
CPU per request. Miniflare does not measure production workerd CPU;
before a release, check the deployed Worker's CPU in the dashboard
against a representative `config=` Preview. Exceeding 10 ms is a plan
limit, not a host-language bug.

### Smoke the deployed URL

Replace `$WORKER_URL` with the HTTPS origin Wrangler printed, including the
scheme and without a trailing slash. These checks stay on-Worker: they do not
fetch an external subscription.

```sh
curl "$WORKER_URL/version"

curl --get "$WORKER_URL/sub" \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

After deploy, replace `/sub` with `/sub/<token>` in the second command.

`GET /version` must print `sub-hub vX.Y.Z backend` for the workspace
version in `Cargo.toml`. The `/sub` response must be Mihomo YAML that
contains that VLESS node. On layout `all`, `GET $WORKER_URL/` must be the
Console HTML.

### Local session

`pnpm run dev` is layout `all`. `pnpm run dev -- --layout worker` skips
Console assets. It is not a substitute for the deployed-runtime smoke above.

A Vite Workshop (`apps/console`, `pnpm run dev`) is a different origin. Point
it at this Worker only after setting `SUB_HUB_CORS_ORIGINS` to
`http://localhost:5173,http://127.0.0.1:5173`. Production same-origin Console
does not need that var.

## Extra aliases (optional)

If this Worker is reachable on more than one hostname (custom domain plus
`*.workers.dev`, or several custom domains), set `SUB_HUB_SELF_HOSTS` to the
comma-separated extra names so a request arriving on one alias cannot fetch
another. A single hostname does not need the var: the inbound host is already
a self-target. A malformed list (non-DNS values, or more than 16 names) makes
the Worker return `500` for every request.

## Cloudflare Git (Workers Builds)

Connect this package as its own Worker. The build image has Node but not
Rust; `scripts/install-workers-toolchain.sh` installs the pinned
toolchain during the Dashboard **Build command**. The **Deploy command**
builds the Console and publishes Wasm plus assets. Do not use
`pnpm run deploy` here: Workers Builds sets `CI=true`, and that script
refuses to run.

| Field | Value |
| --- | --- |
| Worker name | `sub-hub` (must match `wrangler.toml`) |
| Root directory | `crates/sub-hub-worker` |
| Build command | `sh scripts/install-workers-toolchain.sh` |
| Deploy command | `sh scripts/workers-builds-deploy.sh` (all). Conversion only: `sh scripts/workers-builds-deploy.sh worker` |
| Non-production deploy | `sh scripts/workers-builds-deploy.sh preview` (add `worker` for Conversion only) |

Set these **Build** variables (not runtime vars) if the image is older
than the pins in the repository-root `mise.toml`. Do not add
`.node-version` or `.nvmrc`.

| Variable | Value |
| --- | --- |
| `NODE_VERSION` | `24.19.0` |
| `PNPM_VERSION` | `11.22.0` |

After the first successful build, set the runtime
`SUB_HUB_ACCESS_TOKEN` **secret** on the Worker. The deploy helper uses
`--keep-vars` so later pushes keep that secret. Console-only Git is a
separate Worker whose root is `apps/console`. A local `pnpm run deploy`
remains the simpler publish.

The repository-root `wrangler.toml`, `.dev.vars.example`, and
`package.json` `build` / `deploy` scripts are the Deploy-to-Cloudflare
contract when the clone root is the whole repository. Layout `all`
publish uses that root `wrangler.toml` so the wizard can rename the
Worker. Cloudflare requires that Git URL to be public. Do not change the
Dashboard **Root directory** in the table above to `.` unless you also
change the script paths.

## Maintainer preview gate

Miniflare exercises host conformance in CI, but it is not the production
Workers runtime. Before a release, upload a non-production preview and run the
same `/version` and direct `/sub` smoke against that preview URL. Remove or
supersede the preview according to the deployment policy.

```sh
pnpm run preview -- --preview-alias <preview-alias>
```

This gate requires a Cloudflare account. CI does not run it and must not hold
Cloudflare credentials or other deployment secrets.
