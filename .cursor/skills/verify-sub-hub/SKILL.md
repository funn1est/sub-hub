---
name: verify-sub-hub
description: >-
  Drive the Sub Hub Web Console served by loopback Native and prove
  Workshop behavior (version badge, preview, Subscription URL, client
  target, download). Use when changing the Console, the Native HTTP
  surface, or how Native launches.
---

# Verify Sub Hub

Drive the Web Console the way an operator does, against a Native Conversion Service this run started. The Console and Conversion Service share one loopback origin. Vite on port 5173 and a Cloudflare Worker are separate surfaces; this skill does not start them.

The harness is `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs`. Run it from the repository root. Feature journeys live in `features/`.

## Launch

Prerequisites on `PATH`: Node `>= 24.19.0` (the `mise.toml` pin, with `corepack`), `cargo` for Rust 1.97.1, and Google Chrome or Chromium (`CHROME_PATH` overrides the lookup).

```sh
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs launch
```

`launch` builds `apps/console` (`corepack pnpm install --frozen-lockfile` and `corepack pnpm run build`) and `target/debug/sub-hub-native` (`cargo build --locked -p sub-hub-native`), then starts that binary. It picks a free `127.0.0.1` port. It does not bind `25500` and it does not attach to a server it did not start.

The child environment sets only:

- `SUB_HUB_BIND=127.0.0.1:<port>`
- `SUB_HUB_CONSOLE_ROOT=<absolute apps/console/dist>`

`SUB_HUB_ACCESS_TOKEN`, `SUB_HUB_CORS_ORIGINS`, and `SUB_HUB_SELF_HOSTS` are removed from the child even if the parent shell has them. Verification stays on anonymous `GET /sub`. There is no database and no migration. A fresh Chrome profile is the empty Console state.

Ready is the stdout line `ready`. Before that line, `launch` has already required:

- the process is `sub-hub-native` and owns `127.0.0.1:<port>`
- stderr contains `sub-hub-native: SUB_HUB_ACCESS_TOKEN is unset; GET /sub is anonymous` and `sub-hub-native: serving Web Console from SUB_HUB_CONSOLE_ROOT`
- `GET /version` is `200` and the body is `sub-hub v<workspace.package.version> backend` from `Cargo.toml`
- `GET /` is `200`, contains `<title>Sub Hub Console</title>`, and sends `cache-control: no-store` and `referrer-policy: no-referrer`
- `GET /sub` with no query is `400` `Invalid target!` (anonymous route, not `401` and not `404`)

`launch` prints `run=`, `pid=`, `origin=`, `version=`, `versionBody=`, `anonymous=yes`, and `evidence=`. Two launches can run side by side; each has its own port, pid, and Chrome profile. `doctor` and `open` without `--run` use the latest run. Pass `--run <id>` to use another one. Never point these commands at a Native process you started yourself.

A failed `launch` kills the pid it started and deletes that run directory. Tear down a ready run with `cleanup` in the Cleanup section.

## Doctor

Run this first whenever a page, badge, or preview looks wrong:

```sh
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs doctor
```

Doctor is read-only. It repeats the Launch checks against the recorded pid and port: process alive, executable path matches the binary from `launch`, bind and console root match, no `SUB_HUB_ACCESS_TOKEN` in the process environment, the pid owns the listen socket, the log lines are present, and the three HTTP checks match the current `Cargo.toml` version. Exit `0` prints the same `run=` / `origin=` / `versionBody=` lines. Any other exit means this instance is not worth driving. Do not retarget the browser at a different origin to make a check pass.

## Drive

`open` starts headless Chrome for this run (`--headless=new`, `--lang=en-US`, `--remote-debugging-address=127.0.0.1`, a fresh `--user-data-dir`, `--no-sandbox`, `--disable-dev-shm-usage`) and opens `origin/`. It clears `localStorage` before the Console boots, then waits until all of these are true together:

- `document.title` is `Sub Hub Console`
- a header button reads `EN`
- `#service-origin` equals the run origin (same-origin discovery filled it)
- the visible text includes `versionBody`
- a `Preview` button is present

The viewport is `1280x1800`. Later commands reconnect to that Chrome. Chrome may log dbus connection failures in a container; `open` is ready when it prints `opened`, not when that log is empty. Stable handles:

| Handle | What it is |
| --- | --- |
| `#service-origin` | Origin field. Label `Origin`. |
| `#access-token` | Access token. The harness refuses to read or fill it. |
| `#source-0` | First source row. The visible row number is `1`. |
| `Clash / Mihomo`, `Quantumult X`, `sing-box`, `Loon`, `Egern`, `Surge` | Client toggles. `aria-pressed=true` is the selected one. |
| `#subscription-url` | Read-only Subscription URL. |
| `Preview` | Button that GETs that URL. Disabled until the URL is previewable. |
| `Original document` | `<summary>` that reveals the response body. |
| `Response headers` | `<summary>` for the exposed headers. |
| `Download` | Button shown after a `200` preview. |
| `Copy URL` | Copies `#subscription-url`. |
| `Other clients` | `<summary>` of the other target URLs. |
| `Add source`, `Clear`, `Paste` | Source-row actions. |

`click --name` matches one enabled `button`, `a`, or `summary` by `aria-label` or exact visible text, then sends a mouse press at its center. `fill --id` focuses that field and emits an `input` event. `key --ctrl --key Enter` sends Ctrl+Enter to the focused field inside `<main>` (the Workshop preview shortcut). `fetch-shown` GETs only the anonymous `/sub` URL currently in `#subscription-url` on this run's origin.

The direct-node fixture is the share URI from the repository Run section:

```sh
FIXTURE='vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha'
```

Do not replace it with a live subscription URL, an `https://` remote, or a real credential. `example.com` in that URI is a node address inside the document; Native must not open a connection to it. Journeys and entry points are in `features/`. Driving one entry point does not verify the others listed in the same file.

## Evidence

Write proof under the `evidence=` directory `launch` printed (`.scratch/verify-sub-hub/evidence/<run-id>/`). That tree is gitignored with the rest of `.scratch/`. Pass `--feature` and `--entry` on `text`, `snapshot`, `screenshot`, `fetch-shown`, `version-get`, and `wait-download`. Each artifact gets a sibling `*.meta` with the feature id, entry id, run id, and origin. `journal.log` in the run's evidence directory records those commands.

Proof standards:

- Exercise the Workshop or the Subscription URL a client would import. Do not call Rust test helpers, vitest, or a test-only route.
- Capture the action and the resulting state. A version badge, a preview card, or a final screenshot alone is not enough.
- For a `200` preview, save the opened Original document text and a GET of the same Subscription URL. The document on screen and the GET body both have to show the node the user typed (`- name: Alpha` for `FIXTURE`).
- `fetch-shown` header file must show `status: 200`, `content-type: text/plain;charset=utf-8`, and `content-disposition` containing `filename="sub-hub-mihomo.yaml"` for the Clash / Mihomo fixture. `profile-update-interval: 24` is part of that Mihomo response.
- There is no dry-run switch. Preview really converts. The fixture has no remote URL, so the only TCP peers of the Native pid during the journey are loopback connections from Chrome and the harness.
- Do not store an access token, a live subscription URL, or a request log of one in the evidence directory.

## Cleanup

```sh
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs cleanup
```

`cleanup` sends `SIGTERM`, then `SIGKILL`, to the Native pid and the Chrome pid recorded for that run (the process group of each pid this harness spawned). It deletes `.scratch/verify-sub-hub/runs/<run-id>/` only. It does not delete `.scratch/verify-sub-hub/evidence/<run-id>/`. It does not signal processes by name. After a failed `open` or journey, run `cleanup` before launching again so the port and Chrome profile do not linger. Confirm the evidence files are still on disk after `cleanup` returns.

## Helpers

The script is the only helper. `chmod +x` is set; invoke it with `node` so the Node 24 binary on `PATH` is the one that runs it.

```sh
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs launch
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs doctor
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs doctor --run "$RUN"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs open
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs fill --id source-0 --value "$FIXTURE"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name Preview
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name "Original document"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs key --ctrl --key Enter
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait --text "- name: Alpha"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-value --id subscription-url --value "$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs read --id service-origin
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs text --feature preview --entry preview-button --out ".scratch/verify-sub-hub/evidence/$RUN/preview/page.txt"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs snapshot --feature preview --entry preview-button --out ".scratch/verify-sub-hub/evidence/$RUN/preview/page.aria.txt"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs screenshot --scroll pre --feature preview --entry preview-button --out ".scratch/verify-sub-hub/evidence/$RUN/preview/page.png"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs fetch-shown --feature preview --entry preview-client-get --body ".scratch/verify-sub-hub/evidence/$RUN/preview/body.txt" --headers ".scratch/verify-sub-hub/evidence/$RUN/preview/headers.txt"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs version-get --feature version --entry version-get --out ".scratch/verify-sub-hub/evidence/$RUN/version/body.txt"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-download --name sub-hub-mihomo.yaml --feature download --entry download-button --out ".scratch/verify-sub-hub/evidence/$RUN/download/sub-hub-mihomo.yaml"
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs cleanup
node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs cleanup --run "$RUN"
```

`read` prints only the field value. `wait` and `wait-value` print `ok`. `fetch-shown` prints `status=<code>` and refuses any URL whose path is not `/sub` on this run's origin.
