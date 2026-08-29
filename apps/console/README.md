# Sub Hub Web Console

Static Workshop PWA for a self-hosted Conversion Service. It assembles a
Subscription URL (`/sub` or `/sub/:token`), previews that same URL with `GET`,
and copies or downloads the result. It is not a second conversion API.

This package lives at `apps/console`. It is not a Cargo crate. This repository
does not operate a public instance.

## Stack

React + Vite 8 + shadcn v4 / Base UI + Tailwind v4 + `vite-plugin-pwa`.
Node 24.19.0 and pnpm 11.22.0 are pinned in the repository-root `mise.toml`.
Chrome and Workshop copy localize to Chinese and English. The Conversion
Service does not: HTTP bodies stay English and ignore `Accept-Language`.

## Develop

Hot reload is two processes: Native Conversion on loopback, Vite Workshop
on another origin.

Terminal 1, from the repository root:

```sh
SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 \
  cargo run --locked -p sub-hub-native
```

Terminal 2, from this directory:

```sh
pnpm install --frozen-lockfile
pnpm run dev
```

Open the Vite URL (usually `http://localhost:5173`). Set Conversion Service
origin to `http://127.0.0.1:25500`, or:

```sh
VITE_DEFAULT_SERVICE_ORIGIN=http://127.0.0.1:25500 pnpm run dev
```

Origin only, never a token. The access token is typed in the page and stored
only in `localStorage`. Loopback Native has no token unless you set
`SUB_HUB_ACCESS_TOKEN`.

Same-origin Native (no Vite, no CORS, no hot reload) after a Console build:

```sh
pnpm run build
# from the repository root
SUB_HUB_CONSOLE_ROOT=apps/console/dist cargo run --locked -p sub-hub-native
```

Then open `http://127.0.0.1:25500/`. When `/version` on that origin succeeds,
the Workshop fills the Conversion Service origin itself.

Preview is a simple `GET`. The Conversion Service does not answer `OPTIONS`.
When the service skipped nodes, Preview shows the counts from
`x-subconverter-skipped`; it does not fetch a second URL.

The Workshop lists 33 INIs from
`https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/`
(18 Online plus 15 Classic / other). `master` moves; the Console does
not pin a commit. The default is no remote
config (`config=` omitted, PROXY/AUTO). A custom HTTPS URL is the only case
that shows a URL field. `URL-REGEX` is emitted for Loon and omitted on other
targets.

## Build

```sh
pnpm test
pnpm run build
```

Output is `dist/`. `public/_headers` is copied into `dist/` and is honored
by Workers Static Assets: `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a CSP of
`default-src 'self'` with `connect-src 'self' http: https:`,
`script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, and
`base-uri 'self'`. Hashed `/assets/*` and `/workbox-*` files are
`Cache-Control: public, max-age=31536000, immutable`. HTML and `sw.js`
keep Cloudflare's default revalidate. `*.workers.dev` responses send
`X-Robots-Tag: noindex`.

The service worker uses `registerType: prompt`, does not runtime-cache
`/sub` or `/version`, and does not navigate-fallback those paths.

## Deploy

From `crates/sub-hub-worker` after `wrangler login`:

```sh
pnpm run deploy
```

Default layout `all` builds this package and uploads `dist/` as assets
on the Conversion Worker. Open that `*.workers.dev` URL. The Workshop fills
the Conversion Service origin from same-origin `/version`. Paste the token.

Console-only (separate origin) is:

```sh
pnpm run deploy:console
pnpm run deploy:worker -- --cors-origin https://sub-hub-console.<subdomain>.workers.dev
```

Git for Console-only: Workers Builds, Worker name `sub-hub-console`, root
`apps/console`, build `pnpm install --frozen-lockfile && pnpm run build`,
deploy the default `npx wrangler deploy`. Then set `SUB_HUB_CORS_ORIGINS`
on Conversion to that exact origin. Do not commit an `account_id` or API
token.

Local toolchains stay in the repository-root `mise.toml`. Do not add
`.node-version`, `.nvmrc`, or other extra version managers in this package.

Layout `all` Git is the Conversion Worker (see
[`crates/sub-hub-worker/README.md`](../../crates/sub-hub-worker/README.md)).
CI builds and tests here and does not deploy. Do not send Cloudflare
credentials in a pull request.

## Manual smoke

Not a CI gate. Replace `$ORIGIN` with the HTTPS Conversion Worker origin,
no trailing slash.

```sh
curl -D - -o NUL "$ORIGIN/"
# Expect 200, title Sub Hub Console, Referrer-Policy: no-referrer,
# CSP default-src 'self'; connect-src 'self' http: https:; script-src 'self'

curl -D - "$ORIGIN/version"
# Expect: sub-hub v0.1.0 backend. No Access-Control-Allow-Origin.
```

In the Web Console, the Conversion Service origin should already be this
page's origin. Set the access token to the operator-kept value (empty only
if the Worker is anonymous). The `/version` probe should show
`sub-hub v0.1.0 backend`. Preview a direct VLESS with `target=clash`; the
body should be Mihomo YAML that contains that node.

Native pairing from `pnpm run dev` still needs
`SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173` and is
not part of the Worker gate. Layout `all` without that var must not
show the localized CORS explanation. Layout `console` against Conversion
must list this origin in `SUB_HUB_CORS_ORIGINS`.

## Persistence and secrets

One `localStorage` key, `sub-hub.console.v1`: locale, theme, origin, token,
sources, target, config URL, `append_info`, `expand` (default on, writes
`expand=true`). Preview bodies stay in memory only.

The token is never a `VITE_*` value and is never written to the Console address
bar. Generated Subscription URLs contain the path token by design.

## License

GNU Affero General Public License v3.0 or later, same as the repository.
