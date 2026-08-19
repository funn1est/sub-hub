# Sub Hub

Sub Hub is a work-in-progress subscription-conversion backend implemented in
Rust, plus a static Web Console that operates a self-hosted Conversion Service.
It accepts selected VLESS, Shadowsocks, Trojan, VMess, Hysteria2, and
TUIC v5 inputs, can load HTTPS subscription resources and strict ACL4SSR
configurations, and renders configurations for Mihomo (Clash-compatible),
Quantumult X, sing-box, Loon, and Egern.

The native service and Cloudflare Worker share the same host-neutral HTTP and
conversion modules. This repository does not operate a public Sub Hub instance;
you must run or deploy one yourself.

See [Security](SECURITY.md) for how to report a vulnerability and what a
deployer should assume. See [Contributing](CONTRIBUTING.md) for local gates
and the current public surface.

## Current HTTP surface

The current compatibility surface contains only:

- `GET /version`
- `GET /sub` and `HEAD /sub`
- `GET /sub/:token` and `HEAD /sub/:token` when `SUB_HUB_ACCESS_TOKEN` is set

`/sub` requires an exact `target` of `clash` or `mihomo` (Mihomo YAML),
`quanx` (Quantumult X), `singbox` (sing-box JSON), `loon` (Loon), or `egern`
(Egern YAML). Its `url` value accepts one to five ordered inputs separated by
`|`: direct VLESS, Shadowsocks, Trojan, v2rayN JSON v2 VMess, or official
Hysteria2 (`hysteria2://` / `hy2://`), or TUIC v5 (`tuic://uuid:password@host:port`)
share URIs, or
HTTPS subscription URLs whose raw/Base64 contents contain supported share URIs.
An optional HTTPS `config` value selects a strict ACL4SSR INI configuration
and its remote Rule Sets. Absent or empty `config=` uses the default PROXY/AUTO
policy; that is not a remote Rule frontend. `URL-REGEX` rules are emitted for
Loon and omitted on the other targets. The Console lists the 18
`ACL4SSR_Online*.ini` files from ACL4SSR `master`
(`https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/`);
that branch moves. Quantumult X skips gRPC nodes and VLESS
Vision without Reality. sing-box keeps those combinations, omits GeoIP CN rules,
and normalizes fallback groups to `urltest` and load-balance groups to
`selector`. Loon keeps TCP Reality+Vision and WebSocket, skips gRPC and unpaired
Vision/Reality, omits process-name rules, and normalizes load-balance groups to
`pcc`. Egern keeps gRPC and Vision without Reality, skips WebSocket+Reality,
omits process-name rules, and maps url-test to `auto_test`. Trojan TCP+TLS and
WebSocket+TLS map on every target; Quantumult X and Egern skip Trojan gRPC; Loon
skips Trojan Reality and gRPC. VMess accepts only JSON v2 (`vmess://` + Base64);
Quantumult X skips `auto`/`zero` and gRPC; Loon keeps only `aes-128-gcm` TCP/WS;
Egern skips cleartext gRPC. Hysteria2 maps salamander, hop, and certificate
pins on Mihomo; Quantumult X skips every Hysteria2 node; sing-box 1.13.14
skips gecko and `pinSHA256`; Loon keeps salamander on a single port and skips
gecko, hop, and pins; Egern keeps salamander, hop, and pins and skips gecko.
TUIC v5 maps uuid+password on Mihomo, sing-box, and Egern; Quantumult X and Loon
skip every TUIC node; Egern skips non-default congestion control. Import a
generated Egern file in store Egern 2.20.0
to confirm it parses; there is no official `egern check` CLI.

The service does not currently expose POST conversion, capabilities, or an
administration API. An optional
`SUB_HUB_ACCESS_TOKEN` may hold up to eight equivalent path tokens and
protects `GET`/`HEAD /sub/:token` when configured; `GET /version` stays public. Unsupported or invalid individual nodes are
skipped, but source/container/config errors remain fatal and a request with no
valid nodes fails. When any node is skipped, `GET`/`HEAD` `/sub` adds
`x-subconverter-skipped` (and `x-subconverter-result: partial` unless the
response is already `lossy`). All remote resources pass through the shared bounded SSRF
broker.

## Run the native backend

The workspace is pinned to Rust 1.97.1. Start the development build with:

```sh
cargo run --locked -p sub-hub-native
```

The safe default listener is `127.0.0.1:25500`. Verify it and convert one direct
share URI with:

```sh
curl http://127.0.0.1:25500/version

curl --get http://127.0.0.1:25500/sub \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

Build the optimized executable with:

```sh
cargo build --locked --release -p sub-hub-native
```

CI launches that release binary on a loopback port and checks `/version` plus
one local VLESS conversion for every released target (`clash`, `mihomo`,
`quanx`, `singbox`, `loon`, `egern`). The fixture does not fetch an external
subscription.

## Rust development

`mise.toml` pins Rust 1.97.1 with `rustfmt`, Clippy, and
`wasm32-unknown-unknown`. `mise install` installs that toolchain through
rustup. `rust-toolchain.toml` matches the same pin so rustup and rust-analyzer
select it without extra env.

`rustfmt.toml` fixes the Rust 2024 style edition and Unix line endings; workspace
lint policy remains centralized in `Cargo.toml`, while `.cargo/config.toml`
contains the Wasm test runner and target-specific `getrandom` configuration.

Run the repository-wide Rust gates from the workspace root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo check --locked -p sub-hub-conversion --target wasm32-unknown-unknown
cargo check --locked -p sub-hub-http --target wasm32-unknown-unknown
```

Use `cargo fmt --all` without `--check` to apply formatting locally. GitHub's `CI` workflow runs
these repository-wide gates and Worker conformance once per revision; the separate Mihomo workflow
is limited to its pinned two-version external acceptance matrix.

## Native deployment boundary

The native host reads five optional environment variables:

- `SUB_HUB_BIND` sets the listener and defaults to `127.0.0.1:25500`.
- `SUB_HUB_SELF_HOSTS` is a comma-separated list of canonical DNS aliases that
  remote loading must reject as self-targets.
- `SUB_HUB_ACCESS_TOKEN` is a comma- or newline-separated list of at most eight
  unreserved path tokens (`A–Z a–z 0–9 - . _ ~`, 1–128 bytes each). When unset
  on loopback, `GET /sub` stays anonymous and the process prints a warning. A
  non-loopback bind with an empty list refuses to start. When set, clients must
  call `GET /sub/<token>`.
- `SUB_HUB_CORS_ORIGINS` is a comma- or newline-separated list of at most eight
  exact Console origins (`https://console.example`,
  `http://localhost:5173`). Unset means no CORS headers. A present-but-empty
  or invalid list refuses to start. A Vite Workshop against loopback needs
  `http://localhost:5173,http://127.0.0.1:5173`.
- `SUB_HUB_CONSOLE_ROOT` is the path to a built Web Console directory
  (`apps/console/dist`). Unset leaves Native as a Conversion Service only.
  A present value that is not a readable directory refuses to start. When
  set, GET/HEAD paths that are not `/version`, `/sub`, or `/sub/:token`
  serve files from that tree (`/` and unknown paths fall back to
  `index.html`). Same-origin Preview does not need CORS.

A non-loopback `SUB_HUB_BIND` is rejected unless `SUB_HUB_SELF_HOSTS` contains
at least one hostname. List every additional deployment alias even when a
reverse proxy forwards to a loopback listener.

The native binary intentionally does not terminate TLS or provide
deployment-wide rate limiting. For a network deployment, keep it behind a
mature reverse proxy that supplies those controls, enforces request and
concurrency limits, and disables or redacts query-string access logs.
Subscription and config URLs commonly contain credentials; do not expose port
25500 directly or log complete request URLs. Set `SUB_HUB_ACCESS_TOKEN` before
sending a real subscription URL to a non-loopback listener.

## Cloudflare Worker

The Worker lives in [`crates/sub-hub-worker`](crates/sub-hub-worker). Deploy
your own copy; this repository does not operate a public instance. A Cloudflare
account, Rust 1.97.1 with the `wasm32-unknown-unknown` target, Node.js 24.19.0 or
newer, and the pinned `worker-build` 0.8.5 are required.

```sh
cargo install worker-build --version 0.8.5 --locked
cd crates/sub-hub-worker
pnpm install --frozen-lockfile
pnpm exec wrangler login
pnpm run build
pnpm run test:host
pnpm run deploy:stack
```

`pnpm run deploy:stack` builds the Web Console, publishes it as Workers
Static Assets (`sub-hub-console`), publishes the Conversion Worker, and
sets `SUB_HUB_CORS_ORIGINS` plus `SUB_HUB_SELF_HOSTS` from the live
origins. Worker-only publishes stay on `pnpm run deploy`. Do not commit
an `account_id`, API tokens, a local `name` rename, or a `.dev.vars` file
with real values. Override the Console or Worker name with
`CLOUDFLARE_PAGES_PROJECT`, `CLOUDFLARE_WORKER_NAME`, or the matching
flags; do not edit the committed names unless you intend that default for
every clone.

The first Worker deploy prints a `*.workers.dev` URL. The stack command
writes that hostname into `SUB_HUB_SELF_HOSTS`. Add every custom-domain
alias the same way (or set `CLOUDFLARE_EXTRA_SELF_HOSTS`) so remote loading
cannot target those names.

`pnpm run deploy` leaves an existing `SUB_HUB_ACCESS_TOKEN` secret, puts a list
you pass with `--tokens-file`, or generates one token and prints it once. Keep
that value in a password manager; Cloudflare cannot show it again. Do not write
tokens into the committed `wrangler.toml`. Clients use
`GET /sub/<token>?target=clash&url=...`. `GET /version` stays public.

To let the Web Console read those responses, set the
`SUB_HUB_CORS_ORIGINS` **var** (not a secret) to that exact origin, for
example `https://sub-hub-console.<subdomain>.workers.dev`. Leave it unset
if no Console will `fetch()` the Worker. A present-but-empty or invalid
list makes every request return `500`.

Smoke the deployed origin without fetching an external subscription:

```sh
curl "$WORKER_URL/version"

curl --get "$WORKER_URL/sub/<token>" \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

Miniflare/workerd conformance in CI is not the production runtime. Before a
release, upload a preview and run the same smoke against that preview URL:

```sh
cd crates/sub-hub-worker
pnpm run preview -- --preview-alias <preview-alias>
```

CI does not hold Cloudflare credentials and does not deploy. The Worker
restricts outbound HTTPS resources to port 443. See the
[Worker deployment notes](crates/sub-hub-worker/README.md) for the runtime
boundary, variable setup, and what not to commit.

### Cloudflare Git

The Web Console can update on push without GitHub secrets. Connect the
repo as a Worker (Workers Builds), set Root directory to `apps/console`,
and leave the deploy command at the default `npx wrangler deploy`.
`apps/console/wrangler.toml` already points at `dist/`. Full notes are in
the [Console deploy notes](apps/console/README.md#connect-to-git).

Workers Builds does not run `mise`. Set `NODE_VERSION` on the project to
the pin in the repository-root `mise.toml` if the image is older. Do not
add `.node-version` or `.nvmrc`.

The production origin is `https://sub-hub-console.<subdomain>.workers.dev`.
Set the Worker `SUB_HUB_CORS_ORIGINS` **var** to that exact origin
(Dashboard or `wrangler deploy --keep-vars`). Do not also run
`deploy:stack` against the same Console Worker.

The Worker is a separate Git connection (Workers Builds, root
`crates/sub-hub-worker`). The build image has Node but not Rust; a
Workers Builds command must install Rust 1.97.1, `wasm32-unknown-unknown`,
and `worker-build` 0.8.5 before `wrangler deploy --keep-vars`. The Worker
name in the dashboard must match `wrangler.toml` (`sub-hub`). Keep
`SUB_HUB_ACCESS_TOKEN` as a Cloudflare **secret**, not a var. A local
`pnpm run deploy` remains the simpler Worker publish.

## Web Console

The Workshop PWA lives in [`apps/console`](apps/console). It points at a
Conversion Service origin you type, collects the access token in its own field,
assembles `GET /sub` or `GET /sub/:token`, previews that same Subscription URL,
and copies or downloads the result. It does not add POST conversion or extra
query switches.

```sh
cd apps/console
pnpm install --frozen-lockfile
pnpm test
pnpm run dev
```

A Vite Workshop against Native loopback needs
`SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173`. The
stack command publishes the Console as a separate Workers Static Assets
project (root `apps/console`, upload `dist/`) and sets the Worker
`SUB_HUB_CORS_ORIGINS` **var** to that exact origin. CI builds and tests
the Console; it does not deploy. See the
[Console notes](apps/console/README.md).

## Compatibility and provenance

Sub Hub is a Rust implementation based on public protocol specifications and
interoperability research. Related open-source projects may be consulted to
understand ecosystem behavior. References to another project do not imply
source-level derivation, drop-in compatibility, affiliation, or endorsement.

Relevant public references include:

- [`tindy2013/subconverter`](https://github.com/tindy2013/subconverter)
- [Shadowsocks SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html)
- [Shadowsocks 2022 Edition](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md)
- [VMessAEAD / VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716)
- [The Trojan Protocol](https://trojan-gfw.github.io/trojan/protocol)

Any third-party dependencies or incorporated materials remain subject to their
respective licenses and notices. Incorporated-material notices are collected in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## License

Sub Hub is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE).

See [SECURITY.md](SECURITY.md) to report a vulnerability and
[CONTRIBUTING.md](CONTRIBUTING.md) for development gates.
