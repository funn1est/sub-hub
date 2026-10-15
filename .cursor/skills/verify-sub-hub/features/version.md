# Conversion Service version

The Workshop shows the Conversion Service identity from `GET /version` and fills Origin with the page's own origin when that response is this service.

## Sub-features

- `version-badge` shows the version body on the Conversion Service card.
- `version-origin` fills the Origin field with this page's origin.
- `version-get` returns the same body from `GET /version` with no token.

## How to get to it (user POV)

- Open the run origin in the browser. Same-origin Native serves the Console at `/` and probes `/version` by itself.
- Request `GET /version` on that origin. This route stays public when a token is configured; this run is anonymous.

## Driving it with verify-sub-hub

Preconditions:

- `doctor` exited 0. Export `RUN` and `ORIGIN` from its `run=` and `origin=` lines, and keep `versionBody` from the `versionBody=` line.
- Do not type an access token.

- **Open the Console.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs open`. The command prints `opened` plus `ORIGIN`. The header reads `Sub Hub Console` and `EN`. The Origin field equals `ORIGIN`. The badge text equals `versionBody`.
- **Record the badge.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs text --feature version --entry version-badge --out ".scratch/verify-sub-hub/evidence/$RUN/version/page.txt"` and `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs screenshot --feature version --entry version-badge --out ".scratch/verify-sub-hub/evidence/$RUN/version/page.png"`. The text and the screenshot contain `Sub Hub Console` and `versionBody`.
- **Read Origin.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs read --id service-origin`. Stdout is `ORIGIN`.
- **GET /version.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs version-get --feature version --entry version-get --out ".scratch/verify-sub-hub/evidence/$RUN/version/body.txt"`. The command prints `status=200`. `version/body.txt` is exactly `versionBody` with no extra newline.

## Gotchas

- The badge's accessible name is `Conversion Service`. The visible text is the body `sub-hub v<version> backend`, not the words `Conversion Service`.
- A spinner with no body means the probe is still running. Wait for `versionBody` before treating the page as ready. `open` already waits for that.
- `versionBody` comes from `Cargo.toml` `workspace.package.version`. Do not hard-code the version digits.
- Skipping `open` reuses `localStorage` key `sub-hub.console.v1` and can show a different origin than this run.
- `GET /version` on a token-protected deployment is still public. This run proves the anonymous case only. A `401` on `GET /sub` means doctor should already have failed.
