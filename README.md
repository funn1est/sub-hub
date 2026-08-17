# Sub Hub

Sub Hub is a work-in-progress subscription-conversion backend implemented in
Rust. It accepts selected VLESS, Shadowsocks, Trojan, and VMess inputs, can load HTTPS
subscription resources and strict ACL4SSR configurations, and generates modern
Mihomo YAML.

The native service and Cloudflare Worker share the same host-neutral HTTP and
conversion modules. This repository does not operate a public Sub Hub instance;
you must run or deploy one yourself.

## Current HTTP surface

The current compatibility surface contains only:

- `GET /version`
- `GET /sub`
- `HEAD /sub`

`/sub` requires an exact `target` of `clash` or `mihomo` (Mihomo YAML),
`quanx` (Quantumult X), `singbox` (sing-box JSON), `loon` (Loon), or `egern`
(Egern YAML). Its `url` value accepts one to five ordered inputs separated by
`|`: direct VLESS, Shadowsocks, Trojan, or v2rayN JSON v2 VMess share URIs, or
HTTPS subscription URLs whose raw/Base64 contents contain supported share URIs.
An optional HTTPS `config` value selects a supported strict ACL4SSR INI
configuration and its remote Rule Sets. Quantumult X skips gRPC nodes and VLESS
Vision without Reality. sing-box keeps those combinations, omits GeoIP CN rules,
and normalizes fallback groups to `urltest` and load-balance groups to
`selector`. Loon keeps TCP Reality+Vision and WebSocket, skips gRPC and unpaired
Vision/Reality, omits process-name rules, and normalizes load-balance groups to
`pcc`. Egern keeps gRPC and Vision without Reality, skips WebSocket+Reality,
omits process-name rules, and maps url-test to `auto_test`. Trojan TCP+TLS and
WebSocket+TLS map on every target; Quantumult X and Egern skip Trojan gRPC; Loon
skips Trojan Reality and gRPC. VMess accepts only JSON v2 (`vmess://` + Base64);
Quantumult X skips `auto`/`zero` and gRPC; Loon keeps only `aes-128-gcm` TCP/WS;
Egern skips cleartext gRPC. Import a generated Egern file in store Egern 2.20.0
to confirm it parses; there is no official `egern check` CLI.

The service does not currently expose POST conversion, capabilities, an
administration API, or Hysteria2 / TUIC. An optional
`SUB_HUB_ACCESS_TOKEN` protects `GET`/`HEAD /sub/:token` when configured;
`GET /version` stays public. Unsupported or invalid individual nodes are
skipped, but source/container/config errors remain fatal and a request with no
valid nodes fails. All remote resources pass through the shared bounded SSRF
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
one local VLESS to Mihomo conversion. The fixture does not fetch an external
subscription.

## Rust development

With [rustup](https://rustup.rs/) installed, commands run from this repository
automatically select Rust 1.97.1 and install the declared `rustfmt` and
`clippy` components plus the `wasm32-unknown-unknown` target from
`rust-toolchain.toml`.

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

The native host reads three optional environment variables:

- `SUB_HUB_BIND` sets the listener and defaults to `127.0.0.1:25500`.
- `SUB_HUB_SELF_HOSTS` is a comma-separated list of canonical DNS aliases that
  remote loading must reject as self-targets.
- `SUB_HUB_ACCESS_TOKEN` is a single unreserved path token (`A–Z a–z 0–9 - . _ ~`,
  1–128 bytes). When unset, `GET /sub` stays anonymous and the process prints a
  warning. When set, clients must call `GET /sub/<token>`.

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
account, Rust 1.97.1 with the `wasm32-unknown-unknown` target, Node.js 22 or
newer, and the pinned `worker-build` 0.8.5 are required.

```sh
cargo install worker-build --version 0.8.5 --locked
cd crates/sub-hub-worker
corepack pnpm install --frozen-lockfile
corepack pnpm exec wrangler login
corepack pnpm run build
corepack pnpm run test:host
corepack pnpm run deploy
```

The first deploy prints a `*.workers.dev` URL. Put that hostname in the
`SUB_HUB_SELF_HOSTS` Worker variable — together with every custom-domain alias
— and deploy again so remote loading cannot target those names. Do not commit
an `account_id`, API tokens, a local `name` rename, or a `.dev.vars` file with
real values.

Set `SUB_HUB_ACCESS_TOKEN` with `wrangler secret put SUB_HUB_ACCESS_TOKEN`
before sending a real subscription URL to a public Worker. Clients then use
`GET /sub/<token>?target=clash&url=...`. `GET /version` stays public. Do not
write the token into the committed `wrangler.toml`.

Smoke the deployed origin without fetching an external subscription:

```sh
curl "$WORKER_URL/version"

curl --get "$WORKER_URL/sub" \
  --data-urlencode 'target=clash' \
  --data-urlencode 'url=vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha' \
  --output sub-hub-mihomo.yaml
```

Miniflare/workerd conformance in CI is not the production runtime. Before a
release, upload a preview and run the same smoke against that preview URL:

```sh
cd crates/sub-hub-worker
corepack pnpm run preview -- --preview-alias <preview-alias>
```

CI does not hold Cloudflare credentials and does not deploy. The Worker
restricts outbound HTTPS resources to port 443. See the
[Worker deployment notes](crates/sub-hub-worker/README.md) for the runtime
boundary, variable setup, and what not to commit.

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
