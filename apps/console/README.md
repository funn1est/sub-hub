# Sub Hub Web Console

Static Workshop PWA for a self-hosted Conversion Service. It assembles a
Subscription URL (`/sub` or `/sub/:token`), previews that same URL with `GET`,
and copies or downloads the result. It is not a second conversion API.

This package lives at `apps/console`. It is not a Cargo crate. This repository
does not operate a public instance.

## Stack

React + Vite 8 + shadcn v4 / Base UI + Tailwind v4 + `vite-plugin-pwa`.
Node is pinned to 22 in `.nvmrc`.

## Develop

From this directory:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm run dev
```

Optional: `VITE_DEFAULT_SERVICE_ORIGIN=http://127.0.0.1:25500` (origin only,
never a token). The access token is typed in the page and stored only in
`localStorage`.

Same-origin Native pairing (no CORS) after a Console build:

```sh
corepack pnpm run build
# from the repository root
set SUB_HUB_CONSOLE_ROOT=apps/console/dist
cargo run --locked -p sub-hub-native
```

Then open `http://127.0.0.1:25500/` and set the Conversion Service origin to
`http://127.0.0.1:25500`.

A Vite Workshop against Native loopback (separate origin) needs:

```sh
SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 cargo run --locked -p sub-hub-native
```

Preview is a simple `GET`. The Conversion Service does not answer `OPTIONS`.
When the service skipped nodes, Preview shows the counts from
`x-subconverter-skipped`; it does not fetch a second URL.

## Build

```sh
corepack pnpm test
corepack pnpm run build
```

Output is `dist/`. `public/_headers` is copied into `dist/` and sets
`Referrer-Policy: no-referrer` plus a CSP of `default-src 'self'` with
`connect-src 'self' http: https:` and `script-src 'self'`.

The service worker uses `registerType: prompt` and does not runtime-cache the
Conversion Service origin.

## Deploy

Create a **separate** Cloudflare Pages project. Do not attach Pages to the
Worker `wrangler.toml`. CI builds this package and does **not** deploy. Do not
put Cloudflare secrets in GitHub Actions, and do not commit an `account_id`,
API token, or Pages project name.

From the repository root, after `wrangler login` (the Worker package pins
Wrangler 4.122.0):

```sh
cd apps/console
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm run build

cd ../../crates/sub-hub-worker
corepack pnpm exec wrangler pages project create <project> --production-branch main
corepack pnpm exec wrangler pages deploy ../../apps/console/dist \
  --project-name <project> \
  --branch main \
  --commit-dirty=true
```

Wrangler may warn that the Worker `wrangler.toml` lacks `pages_build_output_dir`.
That is expected; ignore it. The upload is the `dist/` directory.

The production origin is `https://<project>.pages.dev`. Pin Node 22 if you later
switch to a Git-connected Pages build (`.nvmrc` is already here). Direct upload
of `dist/` does not run a cloud build.

Then list that exact origin on the Conversion Service. No host-suffix wildcards.
Preview `*.pages.dev` hashes must be added as extra exact origins if those
previews should read `/sub`.

```sh
# Worker — keep existing vars and the access-token secret
corepack pnpm exec wrangler deploy --keep-vars \
  --var SUB_HUB_CORS_ORIGINS:https://<project>.pages.dev

# Native
set SUB_HUB_CORS_ORIGINS=https://<project>.pages.dev
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

In the Pages Console, set the Conversion Service origin to `$WORKER` and the
access token to the operator-kept value (empty only if the Worker is anonymous).
The `/version` probe should show `sub-hub v0.1.0 backend`. Preview a direct
VLESS with `target=clash`; the body should be Mihomo YAML that contains that
node.

A Worker **without** this Console origin in `SUB_HUB_CORS_ORIGINS` must show the
localized CORS / network explanation, not a fake `401 Unauthorized!`. (A listed
origin plus a missing token is a real `401 Unauthorized!` and is correct.)

Native pairing from `pnpm run dev` still needs
`SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173` and is not
part of the Pages gate.

## Persistence and secrets

One `localStorage` key, `sub-hub.console.v1`: locale, theme, origin, token,
sources, target, config URL, `append_info`. Preview bodies stay in memory only.

The token is never a `VITE_*` value and is never written to the Console address
bar. Generated Subscription URLs contain the path token by design.

## License

GNU Affero General Public License v3.0 or later, same as the repository.
