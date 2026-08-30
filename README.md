# Sub Hub

English | [中文](README.zh-CN.md)

Sub Hub is a work-in-progress subscription-conversion backend implemented in
Rust, plus a static Web Console that operates a self-hosted Conversion Service.
It accepts selected VLESS, Shadowsocks, Trojan, VMess, Hysteria2, and
TUIC v5 inputs, can load HTTPS subscription resources and strict ACL4SSR
configurations, and renders configurations for Mihomo (Clash-compatible),
Quantumult X, sing-box, Loon, Egern, and Surge.

The native service and Cloudflare Worker share the same host-neutral HTTP and
conversion modules. This repository does not operate a public Sub Hub instance;
you must run or deploy one yourself.

See [Security](SECURITY.md) for how to report a vulnerability and what a
deployer should assume. See [Contributing](CONTRIBUTING.md) for local gates
and the current public surface.

Work-in-progress means the HTTP surface is closed, not that self-host is
unfinished. This repository does not operate a public instance.

## Run

```sh
git clone https://github.com/funn1est/sub-hub
cd sub-hub
mise install
cargo run --locked -p sub-hub-native
```

The safe default listener is `127.0.0.1:25500`:

```sh
curl http://127.0.0.1:25500/version

curl --get http://127.0.0.1:25500/sub \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

## Current HTTP surface

The current compatibility surface contains only:

- `GET /version`
- `GET /sub` and `HEAD /sub`
- `GET /sub/:token` and `HEAD /sub/:token` when `SUB_HUB_ACCESS_TOKEN` is set

`/sub` requires an exact `target` of `clash` or `mihomo` (Mihomo YAML),
`quanx` (Quantumult X), `singbox` (sing-box JSON), `loon` (Loon), `egern`
(Egern YAML), or `surge` (Surge). Surfboard imports `surge`. Stash, Clash
Verge Rev, FlClash, Clash Meta for Android, and OpenClash import `clash`
(or `mihomo`). Karing and Hiddify import `clash` or `singbox`. Quantumult X,
Loon, and Egern stay on their own tokens. Do not add `stash`, `surfboard`,
or `shadowrocket`. The `url` value accepts one or more ordered inputs separated by
`|`: supported share URIs (VLESS, Shadowsocks, Trojan, v2rayN JSON v2 VMess,
Hysteria2 `hysteria2://` / `hy2://`, TUIC v5
`tuic://uuid:password@host:port`) or HTTPS subscription URLs whose raw/Base64
contents contain those URIs. A GET/HEAD request-target over 8 KiB returns 414.
Remote, decode, and node budgets still fail closed as
`Resource limit exceeded!`. An optional HTTPS `config` value selects a strict
ACL4SSR INI configuration and its remote Rule Sets. Absent or empty `config=`
uses the default PROXY/AUTO policy; that is not a remote Rule frontend.
Omit `expand` or set `expand=false` to leave HTTPS subscriptions and Online
Rule Sets as client remote refs on targets that can name them:
`clash`/`mihomo` (`proxy-providers` / `rule-providers`), `egern`
(`external` / `rule_set`), `loon` (`[Remote Proxy]` / `[Remote Rule]`),
`surge` (`policy-path=` / `RULE-SET`), and
`quanx` subscriptions (`[server_remote]`). Quantumult X remote resources are
QX snippets by default; Loon may need a client `resource-parser` for a
generic Clash YAML or Base64 share-URI container. Sub Hub does not emit that
parser. `quanx` still inlines ACL4SSR Online `.list` files (Clash
`DOMAIN-SUFFIX` is not QX `HOST-SUFFIX`; no `[filter_remote]`). Explicit
`expand=true` inlines remotes through Unique-flight as before. The Web
Console switch defaults on and writes `expand=true`. `singbox` still inlines
when `expand` is omitted.
`URL-REGEX` is emitted for Loon and Surge and omitted on the other targets.
Surge skips every VLESS node (the Manual has no `vless` type). Generic
share-URI or Clash YAML remotes named via `policy-path=` may fail on the
client; Sub Hub does not add a second conversion hop. Quantumult X
skips gRPC, VLESS Vision without Reality, `auto`/`zero` VMess, and every
Hysteria2 and TUIC node, and omits process-name rules. sing-box omits GeoIP CN,
maps fallback to `urltest` and load-balance to `selector`, and skips Hysteria2
gecko and `pinSHA256`. Loon skips gRPC, unpaired Vision/Reality, Trojan Reality,
hop/pins/gecko, and every TUIC node, omits process-name rules, and maps
load-balance to `pcc`. Egern skips Trojan gRPC, cleartext VMess gRPC, Hysteria2
gecko, and non-default TUIC congestion, omits process-name rules, and maps
url-test to `auto_test`. VLESS WebSocket+Reality is a parse reject on every
target; Trojan WebSocket+Reality is kept on Egern. The Console lists 33 INIs from ACL4SSR `master`
(`https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/`):
18 Online plus 15 Classic / other. That branch moves. Import a generated Egern file in store Egern 2.20.0 to
confirm it parses; there is no official `egern check` CLI.

The service does not currently expose POST conversion, capabilities, or an
administration API. An optional
`SUB_HUB_ACCESS_TOKEN` may hold up to eight equivalent path tokens and
protects `GET`/`HEAD /sub/:token` when configured; `GET /version` stays public. Unsupported or invalid individual nodes are
skipped, but source/container/config errors remain fatal and a request with no
valid nodes fails. When any node is skipped, `GET`/`HEAD` `/sub` adds
`x-subconverter-skipped` (and `x-subconverter-result: partial` unless the
response is already `lossy`). All remote resources pass through the shared bounded SSRF
broker. The built-in PROXY/AUTO probe host (`BUILTIN_AUTO_PROBE_URL`,
`https://www.gstatic.com/generate_204`) and the ACL4SSR Classic local-path
rewrite to `raw.githubusercontent.com` are deliberate product constants, not
test fixtures.

## Run the native backend

GitHub Releases whose tag equals `v` plus the workspace version attach
unsigned native binaries for linux-amd64, windows-amd64, and macos-arm64.
Extract the archive and run `sub-hub-native` (or `sub-hub-native.exe` on
Windows). Those downloads are a convenience for running without a Rust
toolchain; they are not signed or notarized, do not include the Web
Console, and may be blocked by SmartScreen or Gatekeeper.

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
subscription. A tag that matches the workspace version publishes the same
release executable for linux-amd64, windows-amd64, and macos-arm64.

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
your own copy; this repository does not operate a public instance.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/funn1est/sub-hub)

The button clones this repository into your GitHub or GitLab account and
runs Workers Builds from the **repository root** (layout `all`: Conversion
plus Console on one origin). Cloudflare requires that Git URL to be
**public**. Set `SUB_HUB_ACCESS_TOKEN` as a Cloudflare **secret** when
prompted; do not copy `.dev.vars.example` to `.dev.vars`. If that secret
is unset, Worker `GET /sub` stays anonymous. Native non-loopback still
refuses to start without tokens. `GET /version` stays public either way.
The button is not a project-hosted instance.

To publish from a machine you already have, a Cloudflare account, Rust
1.97.1 with the `wasm32-unknown-unknown` target, Node.js 24.19.0 or newer,
and the pinned `worker-build` 0.8.5 are required.

```sh
cargo install worker-build --version 0.8.5 --locked
cd crates/sub-hub-worker
pnpm install --frozen-lockfile
pnpm exec wrangler login
pnpm run build
pnpm run test:host
pnpm run deploy
```

`pnpm run deploy` is the `all` layout: one Worker, Console assets on
that same origin. That fits Cloudflare Workers Free (compressed script
under 3 MB gzip; static assets are a separate, free quota). Open the
printed `*.workers.dev` URL; paste the access token into the page.

Conversion only: `pnpm run deploy:worker`. Console only:
`pnpm run deploy:console` (then set `SUB_HUB_CORS_ORIGINS` on Conversion
with `--cors-origin`). Do not commit an `account_id`, API tokens, a local
`name` rename, or a `.dev.vars` file with real values.
`.dev.vars.example` in `crates/sub-hub-worker` is button schema only; do not
copy it. Override the Worker
name with `CLOUDFLARE_WORKER_NAME` or `--worker-name`; do not edit the
committed name unless you intend that default for every clone.

`pnpm run deploy` leaves an existing `SUB_HUB_ACCESS_TOKEN` secret, puts a list
you pass with `--tokens-file`, or generates one token and prints it once. Keep
that value in a password manager; Cloudflare cannot show it again. Do not write
tokens into the committed `wrangler.toml`. Clients use
`GET /sub/<token>?target=clash&url=...`. `GET /version` stays public.
Same-origin Console does not need `SUB_HUB_CORS_ORIGINS`. Extra DNS aliases
(custom domain plus `*.workers.dev`) can be listed in `SUB_HUB_SELF_HOSTS`;
a single hostname does not need that var.

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

Connect the repo as one Worker (Workers Builds, root
`crates/sub-hub-worker`). That publish includes the Web Console. The
repository-root `package.json` `build` / `deploy` scripts call the same
helpers when the clone root is the whole repository (the Deploy-to-Cloudflare
button at the start of this section). The build
image has Node but not Rust; use `sh scripts/install-workers-toolchain.sh`
as the Build command and `sh scripts/workers-builds-deploy.sh` as the
Deploy command. Those scripts install Rust 1.97.1,
`wasm32-unknown-unknown`, and `worker-build` 0.8.5, build the Console,
and run `wrangler deploy --keep-vars`. The Worker name in the dashboard
must match `wrangler.toml` (`sub-hub`).

Workers Builds does not run `mise`. Set `NODE_VERSION` and `PNPM_VERSION`
on the project to the pins in the repository-root `mise.toml` if the image
is older. Do not add `.node-version` or `.nvmrc`. After the first
successful build, set the `SUB_HUB_ACCESS_TOKEN` **secret** (not a var).
Workers Builds does not put that secret; an unset secret leaves `GET /sub`
anonymous. Do not use `pnpm run deploy` on Workers Builds (`CI=true` makes it
refuse). Conversion-only Git uses `sh scripts/workers-builds-deploy.sh worker`.
Console-only Git is a second Worker with root `apps/console`. A local
`pnpm run deploy` remains the simpler publish.

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

Hot reload is that Vite process plus Native. From the repository root, in
another terminal:

```sh
SUB_HUB_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 \
  cargo run --locked -p sub-hub-native
```

Set the Workshop origin to `http://127.0.0.1:25500`. Layout `all` on a
deployed Worker is same-origin and does not need CORS. CI builds and tests
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
It is commonly deployed as a network service; AGPL section 13 requires
operators of modified network-facing versions to offer corresponding source
to their users. Commercial use remains permitted under the AGPL.

See [SECURITY.md](SECURITY.md) to report a vulnerability and
[CONTRIBUTING.md](CONTRIBUTING.md) for development gates.
