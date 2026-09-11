import type { Copy } from "./types.ts"

export const en: Copy = {
  htmlLang: "en",
  ogLocale: "en_US",
  otherLocaleLabel: "中文",
  title: "Sub Hub — self-hosted subscription conversion",
  description:
    "Self-hosted Conversion Service and Web Console. Convert selected VLESS, Shadowsocks, Trojan, VMess, Hysteria2, and TUIC v5 sources into Mihomo, Quantumult X, sing-box, Loon, Egern, and Surge. This project does not operate a public instance.",
  skipToContent: "Skip to content",
  brand: "Sub Hub",
  languageNav: "Language",
  tagline: "Self-hosted Conversion Service and Web Console",
  noPublicInstance: "This repository does not operate a public instance.",
  heroLead:
    "A work-in-progress Rust conversion backend plus a static Web Console that operates a Conversion Service you run. Native and the Cloudflare Worker share the same host-neutral HTTP and conversion modules. You clone, run, or deploy your own copy.",
  ctaRepo: "Source",
  ctaReleases: "Native binaries",
  ctaDeployHint:
    "The button publishes Conversion plus Console on one Worker origin. It does not collect an access token. After deploy, GET /sub stays anonymous until you add SUB_HUB_ACCESS_TOKEN as a Secret.",
  ctaDeployAlt: "Deploy to Cloudflare",
  inputsTitle: "Inputs",
  inputsLead:
    "url accepts one or more ordered sources separated by |. Unsupported or invalid nodes are skipped; source and config errors fail the request.",
  inputs: [
    {
      name: "VLESS",
      detail: "vless:// share URI. TCP, WebSocket, and gRPC with TLS or Reality, including Vision where the target can keep it.",
    },
    {
      name: "Shadowsocks",
      detail:
        "SIP002 ss://. Closed ciphers: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, and the two 2022-blake3-aes-*-gcm methods. simple-obfs http/tls is kept on most targets; Surge skips it.",
    },
    {
      name: "Trojan",
      detail: "trojan://. TCP+TLS and WebSocket+TLS.",
    },
    {
      name: "VMess",
      detail: "vmess:// plus v2rayN JSON v2. Other VMess dialects are rejected.",
    },
    {
      name: "Hysteria2",
      detail: "hysteria2:// and hy2://. Hop, salamander, and pin follow per-target Keep-pass.",
    },
    {
      name: "TUIC v5",
      detail: "tuic://uuid:password@host:port with a closed query set.",
    },
    {
      name: "HTTPS subscriptions",
      detail:
        "Remote contents that contain those share URIs. Omit expand or set expand=false to leave remotes as client refs on targets that can name them. expand=true inlines. sing-box still inlines when expand is omitted.",
    },
    {
      name: "ACL4SSR config",
      detail:
        "Optional HTTPS config= selects a strict ACL4SSR INI. Absent or empty config= is the default PROXY/AUTO policy, not an ACL4SSR profile and not a second Rule frontend.",
    },
  ],
  policyTitle: "Policy and query",
  policyItems: [
    "Absent or empty config= uses PROXY/AUTO (select AUTO + nodes + Direct, url-test AUTO, MATCH → PROXY).",
    "expand is accepted. The Web Console switch defaults on and writes expand=true.",
    "filename is a download-name stem (1–64 bytes). The service appends the per-target extension. Omitted uses sub-hub-<target>.<ext>.",
    "A GET/HEAD request-target over 8 KiB returns 414.",
  ],
  outputsTitle: "Client targets",
  outputsLead:
    "target must be one of these exact tokens. Popular apps that import the document are listed; those names are not extra HTTP tokens. Do not use stash, surfboard, or shadowrocket as target.",
  outputs: [
    {
      token: "clash / mihomo",
      format: "Mihomo YAML. clash is the Clash-compatible name; Clash Meta clients typically import clash.",
      clients:
        "Clash Verge Rev, FlClash, Clash Meta for Android, Stash, OpenClash, Karing, Hiddify",
    },
    {
      token: "quanx",
      format: "Quantumult X conf.",
      clients: "Quantumult X",
    },
    {
      token: "singbox",
      format: "sing-box JSON.",
      clients: "SFA, SFI/SFM, GUI.for.sing-box, Throne, Karing, Hiddify, NekoBox",
    },
    {
      token: "loon",
      format: "Loon conf.",
      clients: "Loon",
    },
    {
      token: "egern",
      format: "Egern YAML.",
      clients: "Egern",
    },
    {
      token: "surge",
      format: "Surge conf. Surfboard follows Surge and does not support VLESS.",
      clients: "Surge, Surfboard",
    },
  ],
  workshopTitle: "Web Console",
  workshopLead:
    "The Workshop PWA lives in apps/console. It points at a Conversion Service origin you type, collects the access token in its own field, assembles GET /sub or GET /sub/:token, previews that same Subscription URL, and copies or downloads the result.",
  workshopItems: [
    "clash://install-config is offered on every platform. On iPhone and iPad it also offers first-party one-click import for Surge, Loon, Egern, and sing-box.",
    "It does not add POST conversion or extra query switches.",
    "Same-origin layout all on a Worker does not need SUB_HUB_CORS_ORIGINS. A Vite Workshop against loopback does.",
  ],
  runTitle: "How to run it",
  runLead:
    "There is no hosted Sub Hub here. Pick Native for a machine you control, GitHub Release binaries if you do not want a Rust toolchain, or the Cloudflare Worker to publish Conversion plus Console.",
  runItems: [
    {
      title: "Native (development)",
      body: "mise install, then cargo run --locked -p sub-hub-native. The safe default listener is 127.0.0.1:25500. Verify with GET /version.",
    },
    {
      title: "Native (GitHub Releases)",
      body: "Unsigned linux-amd64, windows-amd64, and macos-arm64 archives. They do not include the Web Console and are not signed or notarized.",
    },
    {
      title: "Cloudflare Worker",
      body: "Deploy-to-Cloudflare publishes layout all: one Worker, Console assets on that same origin. GET /version stays public. Set SUB_HUB_ACCESS_TOKEN as a Secret on a public Worker so clients use GET /sub/<token>.",
    },
  ],
  httpTitle: "Closed HTTP surface",
  httpLead: "The current compatibility surface contains only:",
  httpRoutes: [
    "GET /version",
    "GET /sub and HEAD /sub",
    "GET /sub/:token and HEAD /sub/:token when SUB_HUB_ACCESS_TOKEN is set",
  ],
  httpNotes: [
    "There is no POST conversion, capabilities endpoint, or administration API.",
    "GET /version stays public when tokens are set. Wrong token: 401 Unauthorized!. Unset token: GET /sub stays anonymous and GET /sub/:token returns 404 Not Found.",
    "When any node is skipped, GET/HEAD /sub adds x-subconverter-skipped (and x-subconverter-result: partial unless the response is already lossy).",
  ],
  notTitle: "Out of scope",
  notItems: [
    "No public conversion instance on this site or in this repository.",
    "No Dockerfile, docker-compose, or GHCR publish job.",
    "No AnyTLS, WireGuard, or SSR. No second Rule frontend.",
    "No extra subconverter switches (include / exclude / emoji / udp / scv / sort).",
  ],
  licenseTitle: "License",
  licenseBody:
    "Sub Hub is licensed under the GNU Affero General Public License v3.0 or later. It is commonly deployed as a network service; AGPL section 13 requires operators of modified network-facing versions to offer corresponding source to their users.",
  sourceLink: "Corresponding source",
  footerNote: "Product intro for the current public surface. Operator detail lives in the README.",
}
