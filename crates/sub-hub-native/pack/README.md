# Sub Hub native

This archive is the Native Conversion Service: one process that serves
`GET /version` and `GET`/`HEAD` `/sub` (and `GET`/`HEAD` `/sub/:token` when
an access token is configured). It does not include the Web Console.

This build is unsigned. Windows SmartScreen and macOS Gatekeeper may warn
on first run.

Corresponding source is the `vX.Y.Z` git tag of the Sub Hub repository that
produced this archive (`AGPL-3.0-or-later`).

## Loopback

On Unix:

```sh
./sub-hub-native
```

On Windows, run `sub-hub-native.exe`. The default listener is
`127.0.0.1:25500`.

```sh
curl http://127.0.0.1:25500/version
```

The body is `sub-hub vX.Y.Z backend`. Loopback `GET /sub` may run without
`SUB_HUB_ACCESS_TOKEN`; the process prints a warning.

## Environment

Set these in the process environment before start. There is no `pref.ini`
and no `.env` file.

- `SUB_HUB_BIND` — listener, default `127.0.0.1:25500`
- `SUB_HUB_SELF_HOSTS` — comma-separated DNS aliases that remote loading
  must reject as self-targets; required for a non-loopback bind
- `SUB_HUB_ACCESS_TOKEN` — comma- or newline-separated path tokens;
  required for a non-loopback bind
- `SUB_HUB_CORS_ORIGINS` — exact Web Console origins; unset means no CORS
- `SUB_HUB_CONSOLE_ROOT` — optional path to a Web Console `dist` you built
  yourself; this archive does not contain one

A non-loopback bind without `SUB_HUB_SELF_HOSTS` and
`SUB_HUB_ACCESS_TOKEN` refuses to start. Put a reverse proxy in front for
TLS and rate limits. Do not log complete request URLs.

The repository README at this tag documents the HTTP surface and the
native deployment boundary.
