# Subscription URL

The Workshop builds the URL a client imports from Origin, the optional access token, the source rows, and the selected client. Preview GETs that same URL.

## Sub-features

- `subscription-textarea` shows the anonymous Clash / Mihomo URL for one direct source.
- `subscription-copy` copies that URL and reports `Copied`.
- `subscription-siblings` lists the other client URLs behind Other clients.

## How to get to it (user POV)

- Read the Subscription URL textarea after Origin and a source are set.
- Choose `Copy URL`.
- Open `Other clients` and use a row's copy button.

## Driving it with verify-sub-hub

Preconditions:

- `doctor` exited 0. Export `RUN` and `ORIGIN`.
- `FIXTURE='vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha'`
- `open` has completed. The access token is empty and the client is `Clash / Mihomo`.
- The expected URL is `$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true`

- **Fill the source.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs fill --id source-0 --value "$FIXTURE"`.
- **Read the textarea.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-value --id subscription-url --value "$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true"`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs read --id subscription-url`. Stdout is that URL and does not contain `/sub/` plus a token segment.
- **Snapshot the field.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs snapshot --feature subscription-url --entry subscription-textarea --out ".scratch/verify-sub-hub/evidence/$RUN/subscription-url/page.aria.txt"`. The `subscription-url` row's value column is the expected URL.
- **Copy.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name "Copy URL"`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait --text Copied`. A toast titled `Copied` means this entry passed. Capture it with `screenshot --feature subscription-url --entry subscription-copy --out ".scratch/verify-sub-hub/evidence/$RUN/subscription-url/copied.png"`.
- **Other clients.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name "Other clients"`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait --text "Quantumult X"`. The list shows Quantumult X, sing-box, Loon, Egern, and Surge. Capture with `--entry subscription-siblings`. Each row's URL uses that target and the same encoded `FIXTURE`.

## Gotchas

- The textarea is read-only. Prove it with `read` and `wait-value`, not by typing into it.
- Headless Chrome often rejects clipboard writes unless the click is a real user gesture and clipboard permission is granted. The harness clicks through the DevTools protocol and does not grant clipboard permission. If the toast is `Could not copy`, record unmet precondition `clipboard write` for `subscription-copy` and do not mark that entry verified. The textarea entry still stands on its own.
- `Copy URL Quantumult X` is the accessible name of a sibling copy button, not the primary `Copy URL` button.
- An empty Origin or an empty source leaves the textarea empty and the placeholder `Fill the origin and at least one source to emit a Subscription URL.`
- Putting a token in `#access-token` changes the path to `/sub/<token>`. This map's expected URL is the anonymous path. The harness refuses to fill `#access-token`.
