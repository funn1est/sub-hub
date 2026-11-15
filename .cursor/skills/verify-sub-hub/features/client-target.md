# Client target

The Client control picks which document the Subscription URL asks for. Clash / Mihomo is one choice (`target=clash`). The other choices are Quantumult X, sing-box, Loon, Egern, and Surge.

## Sub-features

- `client-switch` changes the pressed client and the capability sentence under the control.
- `client-url` rewrites `target=` on the Subscription URL for the same source.

## How to get to it (user POV)

- Choose a client name in the Client toggle row: `Clash / Mihomo`, `Quantumult X`, `sing-box`, `Loon`, `Egern`, or `Surge`.

## Driving it with verify-sub-hub

Preconditions:

- `doctor` exited 0. Export `RUN` and `ORIGIN`.
- `FIXTURE='vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha'`
- `open` has completed and `#source-0` has been filled with `FIXTURE`.
- Clash / Mihomo is pressed, and `#subscription-url` is `$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true`.

- **Switch to Quantumult X.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name "Quantumult X"`. The page shows `Quantumult X skips every Hysteria2 and TUIC node.`
- **Read the URL.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-value --id subscription-url --value "$ORIGIN/sub?target=quanx&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true"`. The command prints `ok`.
- **Record the toggle.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs snapshot --feature client-target --entry client-switch --out ".scratch/verify-sub-hub/evidence/$RUN/client-target/page.aria.txt"` and `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs screenshot --feature client-target --entry client-switch --out ".scratch/verify-sub-hub/evidence/$RUN/client-target/page.png"`. The snapshot row for `Quantumult X` has `pressed` value `true`, and `Clash / Mihomo` does not.
- **Return to Clash / Mihomo.** Run `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs click --name "Clash / Mihomo"`, then `node .cursor/skills/verify-sub-hub/scripts/verify-sub-hub.mjs wait-value --id subscription-url --value "$ORIGIN/sub?target=clash&url=vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha&expand=true"`. Later preview journeys in this run expect `target=clash` again.

## Gotchas

- `Clash / Mihomo` writes `target=clash`. There is no separate Mihomo toggle. A stored `mihomo` value remaps to this choice only after a reload of saved state; a fresh `open` starts on `clash`.
- Do not choose `Preview` on Surge with `FIXTURE`. Surge skips every VLESS node, and the Preview card then reports `No nodes were found`. That is the client capability, not a failed toggle. This journey does not preview.
- The capability sentence is Workshop copy for the selected client. It is not an HTTP header.
- One-click import links other than `Open in Clash` depend on an iPhone or iPad user agent. This harness does not set one, so those links stay absent. `Open in Clash` appears for the Clash / Mihomo choice once the URL exists.
