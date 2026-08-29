/**
 * GET Conversion Service contract adapter used by the Workshop.
 *
 * HTTP (`sub-hub-http`) plus `testdata/subscription-url/cases.json` are the
 * spelling authority. This module encodes a Subscription URL, percent-decodes
 * paste input, and parses Keep-pass skip headers Preview consumes. It does not
 * emit skip headers. Do not generate TypeScript from Rust DTOs.
 *
 * `append_info` captures `subscription-userinfo` on a single remote source.
 * It does not control `profile-update-interval` (Mihomo always sends `24`).
 * `clash` and `mihomo` are wire aliases for the same Client Format Adapter.
 */

export const TARGETS = [
  "clash",
  "mihomo",
  "quanx",
  "singbox",
  "loon",
  "egern",
  "surge",
] as const

export type Target = (typeof TARGETS)[number]

/** HTTP 414 when GET/HEAD request-target length is greater than this. */
export const GET_TARGET_LIMIT_BYTES = 8192

export const QUERY_KEYS = [
  "target",
  "url",
  "config",
  "append_info",
  "insert",
  "expand",
] as const

export const KNOWN_SERVICE_ERRORS = [
  "Invalid target!",
  "Invalid request!",
  "No nodes were found!",
  "Resource limit exceeded!",
  "Unauthorized!",
  "Not Found",
  "Method Not Allowed",
  "URI Too Long",
  "Bad Gateway",
  "Gateway Timeout",
  "Internal Server Error",
] as const

export type KnownServiceError = (typeof KNOWN_SERVICE_ERRORS)[number]

const KNOWN_ERROR_SET = new Set<string>(KNOWN_SERVICE_ERRORS)
const QUERY_KEY_SET = new Set<string>(QUERY_KEYS)

export const SKIPPED_HEADER = "x-subconverter-skipped"

export const EXPOSED_HEADERS = [
  "content-disposition",
  "profile-update-interval",
  "subscription-userinfo",
  "x-subconverter-result",
  "x-subconverter-omitted-rules",
  SKIPPED_HEADER,
] as const

export const VERSION_PATH = "/version"
export const VERSION_BODY = /^sub-hub v\d+\.\d+\.\d+ backend$/

export function isTarget(value: string): value is Target {
  return (TARGETS as readonly string[]).includes(value)
}

export function isKnownServiceError(body: string): body is KnownServiceError {
  return KNOWN_ERROR_SET.has(body)
}

export function isQueryKey(key: string): boolean {
  return QUERY_KEY_SET.has(key)
}

/** HTTP `query.rs`: ASCII `http://` prefix is rejected. */
export function isHttpSource(source: string): boolean {
  return source.slice(0, 7).toLowerCase() === "http://"
}

export function fallbackDownloadName(target: Target): string {
  switch (target) {
    case "clash":
    case "mihomo":
      return "sub-hub-mihomo.yaml"
    case "quanx":
      return "sub-hub-quanx.conf"
    case "singbox":
      return "sub-hub-singbox.json"
    case "loon":
      return "sub-hub-loon.conf"
    case "egern":
      return "sub-hub-egern.yaml"
    case "surge":
      return "sub-hub-surge.conf"
  }
}

/** HTTP `subscription_response_for`: sing-box is JSON, every other target is text. */
export function subscriptionMediaType(target: Target): string {
  switch (target) {
    case "singbox":
      return "application/json;charset=utf-8"
    case "clash":
    case "mihomo":
    case "quanx":
    case "loon":
    case "egern":
    case "surge":
      return "text/plain;charset=utf-8"
  }
}

export type SkipCounts = {
  parse: number
  capability: number
  name: number
}

/** HTTP `query.rs`: `+` is literal, not space. Rejects NUL / CR / LF. */
export function percentDecodeValue(raw: string): string | null {
  const input = new TextEncoder().encode(raw)
  const decoded = new Uint8Array(input.length)
  let out = 0
  let index = 0
  while (index < input.length) {
    if (input[index] === 0x25) {
      const high = hexValue(input[index + 1])
      const low = hexValue(input[index + 2])
      if (high === undefined || low === undefined) {
        return null
      }
      decoded[out] = (high << 4) | low
      out += 1
      index += 3
    } else {
      decoded[out] = input[index]
      out += 1
      index += 1
    }
  }
  const slice = decoded.subarray(0, out)
  if (slice.some((byte) => byte === 0 || byte === 0x0d || byte === 0x0a)) {
    return null
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(slice)
  } catch {
    return null
  }
}

function hexValue(byte: number | undefined): number | undefined {
  if (byte === undefined) {
    return undefined
  }
  if (byte >= 0x30 && byte <= 0x39) {
    return byte - 0x30
  }
  if (byte >= 0x61 && byte <= 0x66) {
    return byte - 0x61 + 10
  }
  if (byte >= 0x41 && byte <= 0x46) {
    return byte - 0x41 + 10
  }
  return undefined
}

export function parseSkippedHeader(value: string | null): SkipCounts | null {
  if (value === null || value.length === 0) {
    return null
  }
  const match = /^parse=(\d+);capability=(\d+);name=(\d+)$/.exec(value)
  if (match === null) {
    return null
  }
  return {
    parse: Number(match[1]),
    capability: Number(match[2]),
    name: Number(match[3]),
  }
}

export type OmittedRules = {
  omittedUrlRegex: number
}

/** HTTP `insert_lossy_headers`: `lossy` + `URL-REGEX=<uint>`. Other tokens stay raw. */
export function parseOmittedRulesHeader(
  result: string | null,
  omitted: string | null
): OmittedRules | null {
  if (result !== "lossy" || omitted === null) {
    return null
  }
  const match = /^URL-REGEX=(\d+)$/.exec(omitted)
  if (match === null) {
    return null
  }
  return { omittedUrlRegex: Number(match[1]) }
}

export type AccessTokenParse = { ok: true; token: string } | { ok: false }

export function parseAccessToken(raw: string): AccessTokenParse {
  if (raw.length === 0) {
    return { ok: true, token: "" }
  }

  const bytes = new TextEncoder().encode(raw)
  if (bytes.length < 1 || bytes.length > 128) {
    return { ok: false }
  }
  if (!/^[A-Za-z0-9._~-]+$/.test(raw)) {
    return { ok: false }
  }
  return { ok: true, token: raw }
}

export type SubGetEncodeInput = {
  accessToken: string
  target: Target
  sources: string[]
  configUrl: string
  appendInfo: boolean
  expand?: boolean
}

export function encodeSubGetTarget(input: SubGetEncodeInput): string {
  const path =
    input.accessToken.length > 0 ? `/sub/${input.accessToken}` : "/sub"
  const queryParts = [
    `target=${input.target}`,
    `url=${encodeURIComponent(input.sources.join("|"))}`,
  ]
  if (input.configUrl.length > 0) {
    queryParts.push(`config=${encodeURIComponent(input.configUrl)}`)
  }
  if (!input.appendInfo) {
    queryParts.push("append_info=false")
  }
  if (input.expand === true) {
    queryParts.push("expand=true")
  }
  return `${path}?${queryParts.join("&")}`
}
