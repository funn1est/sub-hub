# Preview a direct share URI

Preview GETs the Subscription URL and shows the Conversion Service document. For the direct VLESS fixture and Clash / Mihomo, that document is Mihomo YAML containing the node named Alpha.

## Sub-features

- `preview-button` runs preview from the Preview button.
- `preview-keyboard` runs the same preview with Ctrl+Enter or Meta+Enter while focus is inside the page.
- `preview-document` shows the node in Original document.
- `preview-client-get` returns that same document from the Subscription URL a client would import.

## How to get to it (user POV)

- Type a share URI in source row 1 and choose `Preview`.
- Type the same URI and press Ctrl+Enter or Meta+Enter while focus is in the page.
- Import the Subscription URL in `#subscription-url` with a client, which is a GET of that URL.

## Driving it with verify-sub-hub

Preconditions:

- `doctor` exited 0. Export `RUN` and `ORIGIN` from its output.
- `FIXTURE='vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha'`
- `open` has completed for this run, so Origin is `ORIGIN`, the header shows `EN`, the access token is empty, the client toggle `Clash / Mihomo` is pressed, and remote config still reads `Nodes only (PROXY/AUTO)`.
- The expected Subscription URL is `$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true`

- **Enter the share URI.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs fill --id source-0 --value "$FIXTURE"`. `#source-0` equals `FIXTURE`.
- **Wait for the Subscription URL.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-value --id subscription-url --value "$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true"`. The command prints `ok`. `Preview` is enabled.
- **Preview from the button.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name Preview`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait --text "Preview bodies contain node credentials"`. The Preview card shows that warning. The warning is the `200` state, not the document.
- **Open the document.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name "Original document"`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait --text "- name: Alpha"`. The opened document includes `proxies:` and `- name: Alpha`.
- **Client GET.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs fetch-shown --feature preview --entry preview-client-get --body ".scratch/verify-sub-hub/evidence/$RUN/preview/body.txt" --headers ".scratch/verify-sub-hub/evidence/$RUN/preview/headers.txt"`. Stdout includes `status=200`. `headers.txt` contains `content-type: text/plain;charset=utf-8`, `content-disposition: attachment; filename="sub-hub-mihomo.yaml"`, and `profile-update-interval: 24`. `body.txt` contains `- name: Alpha` and `example.com`.
- **Proof.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs text --feature preview --entry preview-button --out ".scratch/verify-sub-hub/evidence/$RUN/preview/page.txt"`, `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs snapshot --feature preview --entry preview-button --out ".scratch/verify-sub-hub/evidence/$RUN/preview/page.aria.txt"`, and `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs screenshot --scroll pre --feature preview --entry preview-button --out ".scratch/verify-sub-hub/evidence/$RUN/preview/page.png"`. `page.txt` contains `Sub Hub Console` and the full `body.txt`. Field values are not part of that text; `page.aria.txt` row `source-0` holds `FIXTURE` and row `subscription-url` holds the expected URL. The screenshot shows `Sub Hub Console`, the source row, and `- name: Alpha`.
- **Keyboard entry.** Run `open` again, repeat the fill and `wait-value` steps, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs key --ctrl --key Enter` and the same `wait --text "Preview bodies contain node credentials"`. Record evidence with `--entry preview-keyboard`. On macOS use `key --meta --key Enter` instead of `--ctrl`. Do not mark `preview-keyboard` verified because `preview-button` passed.

## Gotchas

- `Preview` stays disabled until Origin and one accepted source are set. `click --name Preview` fails with `matches=0` while it is disabled.
- Original document starts folded. `innerText` does not include the YAML until that summary is opened. A screenshot of the warning without the opened document misses the node.
- The warning text is not the converted document. Compare `page.txt` with `body.txt`.
- `expand` defaults on and the URL includes `expand=true`. A profile that skipped `open` can omit it.
- An `http://` source is rejected. A `|` inside one row marks that row invalid. `FIXTURE` has neither.
- Surge skips VLESS. This journey stays on Clash / Mihomo. A `400` `No nodes were found!` here means the client toggle moved.
- Do not point a source at an `https://` subscription. That fetches a remote host and is not this journey. `FIXTURE` must not produce a TCP connection from Native to `example.com`. The Mihomo document names a health-check URL in the `AUTO` group; that string is document text. The Native pid's sockets stay on `127.0.0.1`.
- `fetch-shown` refuses a path other than `/sub`. A filled access token makes the textarea use `/sub/<token>` and the command fails on purpose.
