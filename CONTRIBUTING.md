# Contributing

Sub Hub is licensed under the [GNU Affero General Public License v3.0 or
later](LICENSE). By opening a pull request you offer your changes under the
same license.

This repository does not operate a public instance. Do not send a real
subscription URL to a shared converter, and do not commit `account_id`, API
tokens, `.dev.vars` values, or an access-token list.
`crates/sub-hub-worker/.dev.vars.example` is button schema only; do not copy
it to `.dev.vars`.

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

Native-release helper (`scripts/`):

```sh
node --test scripts/workspace-version.test.mjs scripts/cut-native-release.test.mjs
```

CI does not deploy to Cloudflare and does not hold Cloudflare credentials.
A `v*` tag that matches the workspace version publishes unsigned Native
binaries. From a clean `origin/main`, cut that tag with `pnpm release`
(patch +1, commit, annotated tag, push) or `pnpm release X.Y.Z` for an
explicit minor or major. Tests and smoke read the workspace version; do
not hard-code `GET /version` bodies. Root `.gitignore` keeps `testdata/`
ignored; do not remove that line. The two goldens already on origin
(`testdata/host-visible-contract.json`,
`testdata/subscription-url/cases.json`) are tracked exceptions. Do not
`git add -f` new testdata unless a maintainer asks. Console tests read
the subscription URL golden. Root `package.json` `build` / `deploy`
stay the Cloudflare button helpers; do not replace them.

Do not modify the existing root `.gitignore` unless a maintainer asks for that
change in the same review.

## Scope

The public HTTP surface is `GET /version` and `GET`/`HEAD` `/sub` (plus
`/sub/:token` when tokens are configured). Absent or empty `config=` is the
default PROXY/AUTO policy, not an ACL4SSR profile. New protocols, client
targets, query keys, or routes need an explicit design review before code. Do
not add POST conversion, `GET /capabilities`, extra subconverter switches
(`include` / `exclude` / `emoji` / `udp` / `scv` / `sort`), a
second rule-file dialect, or AnyTLS / WireGuard / SSR in a drive-by PR.
`expand` is an accepted query key: omitted or `false` leaves client remote
refs when the target can name them; `expand=true` inlines remotes.
`filename` is an accepted query key: a download-name stem (1..=64 bytes, no
path or Windows reserved characters). The service appends the per-target
extension. Omitted uses `sub-hub-<target>.<ext>`.
Do not add a Dockerfile, `docker-compose.yml`, or GHCR publish job. Native
without a Rust toolchain is the GitHub Release binaries; Cloudflare is the
Worker in `crates/sub-hub-worker`.

Bug fixes and tests for the current surface are welcome. Match the surrounding
style: secret-safe `Debug`, closed error text, and byte-stable conversion
goldens unless the change is supposed to alter output.
