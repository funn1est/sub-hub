# Agent notes

Tracked operating notes for agents in this repository. Public surface, gates,
and forbids live in `CONTRIBUTING.md`. Do not duplicate that document here.

## Paths that do not travel with a clone

Root `.gitignore` is a closed set. Do not modify it unless a maintainer names
that change in the same review (`CONTRIBUTING.md`). Do not `git add -f` the
paths below unless a maintainer asks.

| Path | Why it is ignored |
| --- | --- |
| `docs/` | Local living surface, research freezes, and `docs/TODO.md`. Public docs are this file, `README.md`, `README.zh-CN.md`, `CONTRIBUTING.md`, and `SECURITY.md`. |
| `CONTEXT.md` | Local vocabulary. If this file is present, use it. English terms stay English. |
| `testdata/` | Extra local fixtures stay off origin. The goldens already on `main` (`testdata/host-visible-contract.json`, `testdata/subscription-url/cases.json`) are tracked; new files here need an explicit `git add -f` in review. |
| `tools/` | Local helper scripts/binaries. |
| `.scratch/` | Local dumps and finished tickets. Not a queue. |
| `.env`, `.dev.vars` | Secrets. Never commit. |
| `node_modules/`, `target/`, `dist/`, `.tmp/`, `.wrangler/` | Install and build output. |

If `docs/` or `CONTEXT.md` is absent, use `CONTRIBUTING.md`, the README pair,
and `SECURITY.md`. Origin will not contain the TODO or the glossary.

## Where work is authorized

- Public surface and forbids: `CONTRIBUTING.md`.
- Public README pair: `README.md` (English, GitHub default) and
  `README.zh-CN.md` (Chinese). They are one document in two languages.
  Changing either — HTTP surface, Run, Native/Worker/Console, env vars,
  forbids, fixtures, or the language switcher — **update both in the same
  change**. Keep sections, commands, and examples aligned. Product terms
  stay English in the Chinese file (see `CONTEXT.md` when present). Do not
  let one side drift. `CONTRIBUTING.md` and `SECURITY.md` stay English-only
  unless a maintainer asks for a Chinese pair.
- If `docs/` is present: operator / packaging guide is `docs/guide.md`;
  living `main` description is the files listed in `docs/README.md`;
  implementation tracker is `docs/TODO.md` (empty Now is a valid state);
  `docs/research/` is dated evidence, not a backlog — do not implement from it.
  Do not start Parked items unless a maintainer asks. Do not start Blocked
  items without the missing prerequisite. Do not implement Won't-do.

## Secrets and fixtures

Treat the working tree, tests, docs, commit messages, and agent replies as if
a stranger will read them.

**Environment and secrets (never write the values):**

- `.env`, `crates/sub-hub-worker/.dev.vars`, password-manager token lists,
  Cloudflare Dashboard secrets, `account_id`, API tokens.
- Binding names are public (`SUB_HUB_ACCESS_TOKEN`, `SUB_HUB_BIND`,
  `SUB_HUB_SELF_HOSTS`, `SUB_HUB_CORS_ORIGINS`, `SUB_HUB_CONSOLE_ROOT`).
  Their **values** are not. Do not echo `env`, `Get-Content .env`, or
  `wrangler secret` output into a commit, a test, `docs/`, or chat.
- Tests use fixtures such as `deployer-token`, `alpha`, `bravo` — not a
  live token. Do not add `.dev.vars.example` or `package.json`
  `cloudflare.bindings`; those collect a value that never becomes a
  Runtime secret.
- `Debug` implementations already redact tokens, URLs, and bodies. Do not
  add `dbg!` / `console.log` of request URLs, `url=` query strings, or
  node credentials.

**Operator-shaped hosts (do not reintroduce):**

| Do not use | Use instead |
| --- | --- |
| `*.f1t.io` (e.g. `sub-hub-console.f1t.io`) | `console.example` (schemeless CORS reject) or `https://console.example` |
| `*.funn1est.workers.dev` (Conversion or Console) | `https://sub-hub.example.workers.dev` / `https://sub-hub-console.example.workers.dev` |
| Real subscription URLs or personal IPs | `example.com`, `127.0.0.1`, RFC5737 docs IPs |

Keep `https://github.com/funn1est/sub-hub` — that is the Deploy-to-Cloudflare
button URL, not a fixture. Do not rewrite `funn1est` as a blanket string
(would smash that URL).

**Ignore / add:**

- Do not `git add` `.env` or `.dev.vars`.
- Do not `git add -f` new `testdata/` files unless a maintainer asks.
  Root `.gitignore` keeps `testdata/` ignored; the two goldens on origin
  are the only tracked exceptions.
- Do not print ignored file contents in review notes.
