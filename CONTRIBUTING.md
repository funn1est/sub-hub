# Contributing

Sub Hub is licensed under the [GNU Affero General Public License v3.0 or
later](LICENSE). By opening a pull request you offer your changes under the
same license.

This repository does not operate a public instance. Do not send a real
subscription URL to a shared converter, and do not commit `account_id`, API
tokens, `.dev.vars` values, or an access-token list.

## Development gates

The workspace is pinned in `mise.toml` (Rust 1.97.1, Node 24.19.0, pnpm
11.22.0). From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo check --locked -p sub-hub-conversion --target wasm32-unknown-unknown
cargo check --locked -p sub-hub-http --target wasm32-unknown-unknown
```

Web Console (`apps/console`):

```sh
pnpm install --frozen-lockfile
pnpm test
pnpm run lint
pnpm run build
```

Worker host conformance (`crates/sub-hub-worker`):

```sh
pnpm install --frozen-lockfile
pnpm run build
pnpm run test:host
```

CI does not deploy to Cloudflare and does not hold Cloudflare credentials.
A `v*` tag that matches the workspace version publishes unsigned Native
binaries.

Do not modify the existing root `.gitignore` unless a maintainer asks for that
change in the same review.

## Scope

The public HTTP surface is `GET /version` and `GET`/`HEAD` `/sub` (plus
`/sub/:token` when tokens are configured). Absent or empty `config=` is the
default PROXY/AUTO policy, not an ACL4SSR profile. New protocols, client
targets, query keys, or routes need an explicit design review before code. Do
not add POST conversion, `GET /capabilities`, extra subconverter switches
(`include` / `exclude` / `emoji` / `filename` / `udp` / `scv` / `sort`), a
second rule-file dialect, or AnyTLS / WireGuard / SSR in a drive-by PR.

Bug fixes and tests for the current surface are welcome. Match the surrounding
style: secret-safe `Debug`, closed error text, and byte-stable conversion
goldens unless the change is supposed to alter output.
