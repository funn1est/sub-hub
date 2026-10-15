# Download the document

After a `200` preview, Download saves the fetched body under the filename the Conversion Service sent. Clash / Mihomo uses `sub-hub-mihomo.yaml`.

## Sub-features

- `download-file` saves that filename and the bytes match the client GET body.

## How to get to it (user POV)

- Choose `Download` on the Preview card after the credential warning is visible.

## Driving it with verify-sub-hub

Preconditions:

- The [preview](./preview.md) button journey has reached the credential warning and `fetch-shown` has written `preview/body.txt` for this `RUN`.
- `doctor` still exits 0 for the same run.
- Chrome was started by `open` for this run, so it has a download directory the harness can see.

- **Download.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name Download`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-download --name sub-hub-mihomo.yaml --feature download --entry download-button --out ".scratch/verify-sub-hub/evidence/$RUN/download/sub-hub-mihomo.yaml"`. The evidence file exists after the command prints its path.
- **Compare bytes.** The evidence file matches `preview/body.txt` byte for byte, including the `- name: Alpha` line.
- **Screenshot.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs screenshot --feature download --entry download-button --out ".scratch/verify-sub-hub/evidence/$RUN/download/page.png"`. `Download` is visible on the Preview card under the credential warning.

## Gotchas

- `Download` is absent until preview status is `200`. An error alert has no Download button. `click --name Download` then fails with `matches=0`.
- The saved name comes from `content-disposition` (`attachment; filename="sub-hub-mihomo.yaml"`), not from the optional Download name field. An empty Download name omits `filename=` from the query and still uses that default.
- `wait-download` copies the file into the evidence path. Cleanup deletes the Chrome download directory and keeps the evidence copy.
- If `wait-download` times out, `download-file` is unverified. Do not treat `preview/body.txt` as the downloaded file. A headless run of this harness clicked `Download` after both download-behavior commands were accepted and the Chrome download directory stayed empty. Record that timeout. A passing entry writes `sub-hub-mihomo.yaml` and matches `preview/body.txt`.
