# Security

This repository does not operate a public Sub Hub instance. You are responsible
for any Native process or Cloudflare Worker you run.

## Report a vulnerability

Use GitHub's private vulnerability reporting on this repository. Do not open a
public issue for a working exploit, a leaked token, or an SSRF path that
reaches a non-public address.

Please include the host (Native or Worker), the request shape **without**
subscription URLs or tokens, and how to reproduce.

## What deployers should assume

- Subscription and `config` URLs commonly contain credentials. They appear in
  the query string of `GET /sub`. Do not log complete request URLs. Put a
  reverse proxy in front of Native for TLS, rate limits, and log redaction.
  The Worker Wrangler config enables Workers Logs with invocation logs off:
  Fetch invocation messages include the request URL.
- `SUB_HUB_ACCESS_TOKEN` is optional. When unset, Worker `GET /sub` stays
  anonymous. When set, conversion is only on `GET`/`HEAD /sub/<token>`.
  `GET /version` stays public. On the Worker, open **Settings** →
  **Runtime variables and secrets**, click **+ Add variable**, and add it
  in **Add environment variable** with **Secret** checked. After save,
  **Value** is **Value encrypted**. An unchecked **Secret** row of the
  same **Name** is visible in the Dashboard and shadows the **Secret**.
  Workers Builds **Build** variables do not reach the isolate. The
  Deploy-to-Cloudflare button does not collect this secret. Keep the token
  list in a password manager. Native still
  refuses to start a non-loopback bind with an empty token list. The Worker
  does not refuse to boot without a token. The token still appears in
  Subscription URLs you copy (`GET /sub/<token>`) and in Console
  `localStorage`; that is the access-token wire form.
- Remote fetches go through a bounded SSRF broker (HTTPS only, DNS hostnames,
  self-host deny, size and time limits). Native additionally refuses loopback,
  RFC1918, link-local, ULA, and CGNAT answers after DNS; Fake-IP `198.18.0.0/15`
  is not in that set. The Worker additionally restricts outbound destinations
  to port 443. The Worker relies on Cloudflare
  `global_fetch_strictly_public` for post-DNS destination policy and does not
  replicate Native's IP checks.
- Individual unsupported nodes are skipped. The config body stays a valid
  client document. Counts are advertised on `x-subconverter-skipped`; that
  header never contains URIs, credentials, or node names.
- The Web Console stores the access token in `localStorage` and previews the
  same Subscription URL a client would import. Preview bodies stay in memory.

## What this project will not treat as in-scope by default

- Operating someone else's self-hosted copy.
- Clients that ignore `x-subconverter-skipped` and therefore cannot see skips.
- Asking the Conversion Service to fetch `http://` or a private/self address
  (those requests are supposed to fail closed).
