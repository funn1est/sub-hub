# Sub Hub Cloudflare Worker

This crate hosts Sub Hub on Cloudflare Workers. The native service and this
Worker share the same host-neutral HTTP and conversion modules.

This repository does not operate a public instance. Deploy your own Worker if
you want a public URL.

## Runtime boundary

The Cloudflare remote adapter accepts only HTTPS destinations on port 443. An
initial URL using another port receives `400`; a redirect to another port
receives `502`. This restriction is specific to the Cloudflare adapter and does
not apply to the native host.

The hostname of the inbound request is always treated as a self-target. Remote
subscription and config URLs must not point at that host.

`SUB_HUB_SELF_HOSTS` is an optional, comma-separated list of additional
canonical DNS aliases that remote loading must also reject. List every
published hostname — the `*.workers.dev` name and any custom domain — so a
request arriving on one alias cannot fetch another.

## Access token

`SUB_HUB_ACCESS_TOKEN` is a Cloudflare **secret** (never a `[vars]` value or a
committed `.dev.vars` file). The blob is a comma- or newline-separated list of
at most eight equivalent tokens. Each token is 1–128 bytes from
`A–Z a–z 0–9 - . _ ~`. Any configured token authorizes `GET`/`HEAD /sub/<token>`.
`GET /sub` then returns `401 Unauthorized!`. `GET /version` stays public.

Cloudflare cannot show the value after save. Keep the full list in a password
manager or an uncommitted file. The Dashboard field can only **replace** that
blob; it is not a viewer. Do not create a `SUB_HUB_ACCESS_TOKEN` **var** — a var
shadows the secret.

`pnpm run deploy` will:

- put the list you pass with `--tokens-file`, `--tokens`, or `--from-env`;
- leave an existing secret unchanged;
- or, when `wrangler secret list` proves the name is absent, generate one
  32-character hex token, put it with the same deploy, and print it once.

It never treats an ambient `SUB_HUB_ACCESS_TOKEN` as a put. If it cannot tell
whether the secret exists, it aborts instead of generating.

```sh
corepack pnpm run deploy -- --tokens-file tokens.txt
corepack pnpm run deploy -- --replace
```

A present-but-empty or malformed secret makes every request return `500`.

Do not log complete request URLs. Query strings commonly contain credentials.

## Prerequisites

- A Cloudflare account
- [rustup](https://rustup.rs/) so this repository can select Rust 1.97.1, the
  `wasm32-unknown-unknown` target, `rustfmt`, and Clippy from
  `rust-toolchain.toml`
- `worker-build` 0.8.5
- Node.js 22 or newer, with Corepack enabled so the pinned pnpm 10.32.1 is
  used

Install the pinned Worker build tool once per machine:

```sh
cargo install worker-build --version 0.8.5 --locked
```

## Self-serve deploy

From this directory:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm exec wrangler login
corepack pnpm run build
corepack pnpm run test:host
corepack pnpm run deploy
```

`pnpm run deploy` runs the access-token ensure script, then `wrangler deploy
--keep-vars` (rebuilds through `worker-build --release` in `wrangler.toml`).
The first successful deploy prints a `*.workers.dev` URL. Save any generated
token immediately; Cloudflare cannot show it again.

If the account already has a Worker named `sub-hub`, change `name` in
`wrangler.toml` locally so the deploy does not collide. Do not commit that
rename, an `account_id`, API tokens, or a `.dev.vars` file that holds real
values.

### Publish every hostname as a self-target

After the first deploy, set `SUB_HUB_SELF_HOSTS` to the Worker hostname and
deploy again. Use a Cloudflare dashboard text variable, or pass the value at
deploy time without writing it into the committed `wrangler.toml`:

```sh
corepack pnpm exec wrangler deploy --var SUB_HUB_SELF_HOSTS:sub-hub.<subdomain>.workers.dev
```

Add every extra custom-domain hostname to the same comma-separated list and
redeploy. A malformed list (non-DNS values, or more than 16 names) makes the
Worker return `500` for every request.

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

`GET /version` must print `sub-hub v0.1.0 backend`. The `/sub` response must
be Mihomo YAML that contains that VLESS node.

### Local session

`corepack pnpm run dev` starts `wrangler dev` against the same build. It is
not a substitute for the deployed-runtime smoke above.

## Maintainer preview gate

Miniflare exercises host conformance in CI, but it is not the production
Workers runtime. Before a release, upload a non-production preview and run the
same `/version` and direct `/sub` smoke against that preview URL. Remove or
supersede the preview according to the deployment policy.

```sh
corepack pnpm run preview -- --preview-alias <preview-alias>
```

This gate requires a Cloudflare account. CI does not run it and must not hold
Cloudflare credentials or other deployment secrets.
