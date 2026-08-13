# Sub Hub Cloudflare Worker

This crate hosts Sub Hub on Cloudflare Workers.

## Runtime boundary

The Cloudflare remote adapter accepts only HTTPS destinations on port 443. An
initial URL using another port receives `400`; a redirect to another port
receives `502`. This restriction is specific to the Cloudflare adapter and does
not apply to the native host.

`SUB_HUB_SELF_HOSTS` is an optional, comma-separated list of additional host
aliases that must be treated as self-targets. The request URL's own hostname is
always denied as a self-target as well.

## Release gate

Miniflare exercises host conformance in CI, but it is not a substitute for the
real Workers runtime. Before a release, manually upload a preview to Cloudflare
and run the smoke checks against that preview. This is a manual release gate;
CI does not require Cloudflare credentials or other deployment secrets.
