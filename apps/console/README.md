# Sub Hub Web Console

Static Workshop PWA for a self-hosted Conversion Service. It assembles a
Subscription URL (`/sub` or `/sub/:token`), previews that same URL with `GET`,
and copies or downloads the result. It is not a second conversion API.
Pasting a Subscription URL into a source row fills the form.

This package lives at `apps/console`. It is not a Cargo crate. This repository
does not operate a public instance.

## Stack

React + Vite 8 + shadcn v4 / Base UI + Tailwind v4 + `vite-plugin-pwa`.
Node 24.19.0 and pnpm 11.22.0 are pinned in the repository-root `mise.toml`.

## Develop

From this directory:

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm run dev
```

Optional: `VITE_DEFAULT_SERVICE_ORIGIN=http://127.0.0.1:25500` (origin only,
never a token). The access token is typed in the page and stored only in
`localStorage`.

Same-origin Native pairing (no CORS) after a Console build:

```sh
pnpm run build
# from the repository root
set SUB_HUB_CONSOLE_ROOT=apps/console/dist
cargo run --locked -p sub-hub-native
```

Then open `http://127.0.0.1:25500/`. When `/version` on that origin succeeds,
the Workshop fills the Conversion Service origin itself. Otherwise set it to
`http://127.0.0.1:25500`.

A Vite Workshop against Native loopback (separate origin) needs:

```sh
SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 cargo run --locked -p sub-hub-native
```

Preview is a simple `GET`. The Conversion Service does not answer `OPTIONS`.
When the service skipped nodes, Preview shows the counts from
`x-subconverter-skipped`; it does not fetch a second URL.

The Workshop lists the 18 `ACL4SSR_Online*.ini` files from
`https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/`.
`master` moves; the Console does not pin a commit. The default is no remote
config (`config=` omitted, PROXY/AUTO). A custom HTTPS URL is the only case
that shows a URL field. `URL-REGEX` is emitted for Loon and omitted on other
targets.

## Build

```sh
pnpm test
pnpm run build
```

Output is `dist/`. `public/_headers` is copied into `dist/` and sets
`Referrer-Policy: no-referrer` plus a CSP of `default-src 'self'` with
`connect-src 'self' http: https:` and `script-src 'self'`.

The service worker uses `registerType: prompt` and does not runtime-cache the
Conversion Service origin.

## Deploy

Create a **separate** Worker for this package. Do not add `[assets]` or a
second `name` to the Conversion Service `wrangler.toml`. The default name
is `sub-hub-console` in this package's `wrangler.toml`; override it per
account instead of committing an `account_id` or API token.

Local toolchains stay in the repository-root `mise.toml`. Do not add
`.node-version`, `.nvmrc`, or other extra version managers in this package.

### Connect to Git

Push to the connected branch rebuilds this package. `wrangler.toml` uses
Workers Static Assets, so the dashboard can keep the default deploy command
(`npx wrangler deploy`). Do not switch it to `wrangler pages deploy`, and
do not set a Pages output directory.

1. [Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages)
   → **Create** → **Worker** → import this repository.
2. Set only the monorepo root (the repository root is not this package):

   | Field | Value |
   | --- | --- |
   | Worker name | `sub-hub-console` (must match `wrangler.toml`) |
   | Root directory | `apps/console` |
   | Build command | `pnpm install --frozen-lockfile && pnpm run build` |
   | Deploy command | leave the default `npx wrangler deploy` |

3. Optional: `NODE_VERSION=24.19.0` if the build image is older than the
   pin in the repository-root `mise.toml`.
4. Save. Production origin is
   `https://sub-hub-console.<subdomain>.workers.dev`.
5. Put that **exact** origin on the Conversion Service
   (`SUB_HUB_CORS_ORIGINS`). No `*.workers.dev` wildcards. Add each preview
   origin the same way if that preview must `fetch()` `/sub`.
6. Optional: **Build watch paths** → `apps/console/**` so Worker-only
   commits do not rebuild the Console.

If this Worker is already Git-connected, push is enough — do not change
the deploy command. Do not also run `pnpm run deploy:stack` against the
same Worker. CI builds this package and does not deploy. Do not send
Cloudflare credentials in a pull request.

Worker-only local publish after `wrangler login` from
`crates/sub-hub-worker`:

```sh
pnpm exec wrangler deploy --keep-vars \
  --var SUB_HUB_CORS_ORIGINS:https://sub-hub-console.<subdomain>.workers.dev
```

### Direct Upload

For a one-shot upload of `dist/` instead of Git (from the Worker package,
which pins Wrangler 4.122.0):

```sh
cd apps/console
pnpm install --frozen-lockfile
pnpm test
pnpm run build

cd ../../crates/sub-hub-worker
pnpm exec wrangler deploy --config ../../apps/console/wrangler.toml
```

`deploy:stack` does that upload and sets the Worker CORS var. Direct
upload does not run a Cloudflare build. Do not Git-connect and Direct-Upload
the same Worker.

Then list that exact origin on the Conversion Service. No host-suffix
wildcards. Preview `*.workers.dev` hashes must be added as extra exact
origins if those previews should read `/sub`.

```sh
# Conversion Service — keep existing vars and the access-token secret
pnpm exec wrangler deploy --keep-vars \
  --var SUB_HUB_CORS_ORIGINS:https://sub-hub-console.<subdomain>.workers.dev

# Native
set SUB_HUB_CORS_ORIGINS=https://sub-hub-console.<subdomain>.workers.dev
```

A present-but-empty or malformed `SUB_HUB_CORS_ORIGINS` makes every Worker
request return `500`.

## Manual smoke

Not a CI gate. Replace `$CONSOLE` and `$WORKER` with the HTTPS origins, no
trailing slash.

```sh
curl -D - -o NUL "$CONSOLE/"
# Expect 200, title Sub Hub Console, Referrer-Policy: no-referrer,
# CSP default-src 'self'; connect-src 'self' http: https:; script-src 'self'

curl -D - "$WORKER/version"
# Expect: sub-hub v0.1.0 backend. No Access-Control-Allow-Origin.

curl -D - -H "Origin: $CONSOLE" "$WORKER/version"
# Expect the same body plus
# Access-Control-Allow-Origin: $CONSOLE
# Vary: Origin

curl -D - -H "Origin: https://evil.example" "$WORKER/version"
# Expect the version body and no Access-Control-* headers.
```

In the Web Console, set the Conversion Service origin to `$WORKER` and the
access token to the operator-kept value (empty only if the Worker is anonymous).
The `/version` probe should show `sub-hub v0.1.0 backend`. Preview a direct
VLESS with `target=clash`; the body should be Mihomo YAML that contains that
node.

A Worker **without** this Console origin in `SUB_HUB_CORS_ORIGINS` must show the
localized CORS / network explanation, not a fake `401 Unauthorized!`. (A listed
origin plus a missing token is a real `401 Unauthorized!` and is correct.)

Native pairing from `pnpm run dev` still needs
`SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173` and is not
part of the Console gate.

## Persistence and secrets

One `localStorage` key, `sub-hub.console.v1`: locale, theme, origin, token,
sources, target, config URL, `append_info`. Preview bodies stay in memory only.

The token is never a `VITE_*` value and is never written to the Console address
bar. Generated Subscription URLs contain the path token by design.

## License

GNU Affero General Public License v3.0 or later, same as the repository.
