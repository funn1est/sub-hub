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

A Vite Workshop against Native loopback needs:

```sh
SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 cargo run --locked -p sub-hub-native
```

Preview is a simple `GET`. The Conversion Service does not answer `OPTIONS`.

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

Create a separate Cloudflare Pages project. Root directory: `apps/console`.
Build command: `corepack pnpm install --frozen-lockfile && corepack pnpm run build`.
Output directory: `dist`. Pin Node 22 (`.nvmrc` is already here).

Deploy by Dashboard or `wrangler pages`. CI builds this package and does **not**
deploy. Do not put Cloudflare secrets in GitHub Actions.

After the Pages origin exists, add it to the Conversion Service:

```sh
# Worker
corepack pnpm exec wrangler deploy --keep-vars --var SUB_HUB_CORS_ORIGINS:https://<project>.pages.dev

# Native
set SUB_HUB_CORS_ORIGINS=https://<project>.pages.dev
```

No host-suffix wildcards. Preview `*.pages.dev` hashes must be listed exactly if
you want those previews to read `/sub`.

## Manual smoke

Not a CI gate.

1. Pages Console → Worker with `SUB_HUB_CORS_ORIGINS` set to that Pages origin.
   Preview a direct VLESS with `target=clash`. The body should be Mihomo YAML.
2. `pnpm run dev` → Native at `http://127.0.0.1:25500` with the Vite origins in
   `SUB_HUB_CORS_ORIGINS`. Same Preview.
3. A Worker **without** CORS must show the localized CORS / network explanation,
   not a fake `401 Unauthorized!`.

## Persistence and secrets

One `localStorage` key, `sub-hub.console.v1`: locale, theme, origin, token,
sources, target, config URL, `append_info`. Preview bodies stay in memory only.

The token is never a `VITE_*` value and is never written to the Console address
bar. Generated Subscription URLs contain the path token by design.

## License

GNU Affero General Public License v3.0 or later, same as the repository.
