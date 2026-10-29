# Sub Hub verification map

This directory is the maintained source for verifying the user-facing Web Console against a loopback Native Conversion Service. Read this index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Run `launch`, then `doctor`, from the repository root. Export `RUN` and `ORIGIN` from the `run=` and `origin=` lines.
- The origin is `http://127.0.0.1:<port>` chosen by that launch. It is not `127.0.0.1:25500` unless that launch printed that port.
- Native is anonymous: `anonymous=yes`, and `GET /sub` with no query is `400` `Invalid target!`.
- `open` has put Chrome on that origin with an empty `localStorage` key `sub-hub.console.v1` and the header button `EN`.
- The direct-node fixture is `FIXTURE='vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha'`.
- Never drive an instance that was not started by this verification run.

## Driving conventions

- Start every recipe from the baseline state unless its preconditions say otherwise.
- Prefer the ids and accessible names in the feature file over coordinates or tab order.
- Treat every command as literal. Keep quoted names and flags unchanged.
- Run browser and HTTP actions through `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs`.
- `open` clears Console `localStorage` before boot. A second journey in the same run starts with `open` again.
- Do not remove proof artifacts during cleanup.

## Proof and skip reporting

- Capture the user action and the resulting state, not only the final screen.
- UI proof includes the `snapshot` file and a `screenshot` with `Sub Hub Console` visible.
- HTTP proof includes status, headers, and body from `version-get` or `fetch-shown`.
- A preview proof includes both the opened Original document and the GET body of the Subscription URL on screen.
- Record the feature id and entry point in `--feature` and `--entry` on every evidence command.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with verify-sub-hub` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only user paths, stable handles, required state, commands, and observable proof.

## Features

- [Conversion Service version](./version.md) covers the same-origin badge and `GET /version`.
- [Preview a direct share URI](./preview.md) covers the Preview button, Ctrl+Enter, the opened document, and the client GET.
- [Subscription URL](./subscription-url.md) covers the textarea, Copy URL, and the other-client list.
- [Client target](./client-target.md) covers the client toggle and the `target=` query.
- [Download the document](./download.md) covers saving `sub-hub-mihomo.yaml` after a `200` preview.
