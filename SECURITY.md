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
- When `SUB_HUB_ACCESS_TOKEN` is set, conversion is only on
  `GET`/`HEAD /sub/<token>`. `GET /version` stays public. Keep the token list
  in a password manager; Cloudflare cannot show a secret after save.
- Remote fetches go through a bounded SSRF broker (HTTPS only, DNS hostnames,
  self-host deny, size and time limits). Native additionally refuses loopback,
  RFC1918, link-local, ULA, and CGNAT answers after DNS; Fake-IP `198.18.0.0/15`
  is not in that set. The Worker additionally restricts outbound destinations
  to port 443.
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
