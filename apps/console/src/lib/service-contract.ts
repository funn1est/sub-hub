/**
 * GET Conversion Service contract used by the Workshop.
 *
 * HTTP (`sub-hub-http`) is the authority. This module is a handwritten adapter
 * for wire tokens, request-target encode/decode, error bodies, skip grammar,
 * and Access token shape. Workshop assembly lives in `workshop.ts`. Do not
 * generate TypeScript from Rust DTOs (ADR-0020 is retired).
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
] as const

export type Target = (typeof TARGETS)[number]

export const MAX_SOURCES = 5
/** HTTP 414 when GET/HEAD request-target length is greater than this. */
export const GET_TARGET_LIMIT_BYTES = 8192

export const QUERY_KEYS = [
  "target",
  "url",
  "config",
  "append_info",
  "insert",
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
  }
}

export type SkipCounts = {
  parse: number
  capability: number
  name: number
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

export function parseSkippedFromHeaders(
  headers: readonly { name: string; value: string }[]
): SkipCounts | null {
  const value =
    headers.find((header) => header.name === SKIPPED_HEADER)?.value ?? null
  return parseSkippedHeader(value)
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
}

export type PasteWarning =
  | "unknown-keys"
  | "duplicate-keys"
  | "invalid-target"
  | "invalid-token"
  | "invalid-append-info"
  | "invalid-insert"
  | "empty-sources"
  | "http-sources"

export type SubGetDecode =
  | {
      ok: true
      origin: string
      accessToken: string
      target?: Target
      sources?: string[]
      configUrl?: string
      appendInfo: boolean
      warnings: PasteWarning[]
    }
  | { ok: false; reason: "invalid-url" }

/** Percent-decode matching HTTP query.rs: `+` is literal, not space. */
function percentDecodeValue(raw: string): string | null {
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
  return `${path}?${queryParts.join("&")}`
}

export function decodeSubGetTarget(raw: string): SubGetDecode {
  const trimmed = raw.trim()
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return { ok: false, reason: "invalid-url" }
  }
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "invalid-url" }
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "invalid-url" }
  }

  const pathname = url.pathname
  const warnings: PasteWarning[] = []
  let accessToken = ""
  if (pathname === "/sub") {
    accessToken = ""
  } else if (pathname.startsWith("/sub/")) {
    const rest = pathname.slice("/sub/".length)
    if (rest.includes("/") || rest.length === 0) {
      return { ok: false, reason: "invalid-url" }
    }
    const parsed = parseAccessToken(rest)
    if (!parsed.ok) {
      warnings.push("invalid-token")
    } else {
      accessToken = parsed.token
    }
  } else {
    return { ok: false, reason: "invalid-url" }
  }

  const origin = `${url.protocol}//${url.host}`
  const decoded: Extract<SubGetDecode, { ok: true }> = {
    ok: true,
    origin,
    accessToken,
    configUrl: "",
    appendInfo: true,
    warnings,
  }

  const rawQuery = url.search.startsWith("?") ? url.search.slice(1) : ""
  if (rawQuery.length === 0) {
    return decoded
  }

  const seen = new Set<string>()
  let unknown = false
  let duplicate = false
  const values = new Map<string, string>()
  for (const pair of rawQuery.split("&")) {
    const eq = pair.indexOf("=")
    if (eq <= 0) {
      return { ok: false, reason: "invalid-url" }
    }
    const key = pair.slice(0, eq)
    const value = percentDecodeValue(pair.slice(eq + 1))
    if (value === null) {
      return { ok: false, reason: "invalid-url" }
    }
    if (!isQueryKey(key)) {
      unknown = true
    }
    if (seen.has(key)) {
      duplicate = true
    }
    seen.add(key)
    if (!values.has(key)) {
      values.set(key, value)
    }
  }
  if (unknown) {
    decoded.warnings.push("unknown-keys")
  }
  if (duplicate) {
    decoded.warnings.push("duplicate-keys")
  }

  const target = values.get("target")
  if (target !== undefined) {
    if (isTarget(target)) {
      decoded.target = target
    } else {
      decoded.warnings.push("invalid-target")
    }
  }

  const urlParam = values.get("url")
  if (urlParam !== undefined && urlParam.length > 0) {
    const sources = urlParam.split("|")
    if (sources.some((source) => source.length === 0)) {
      decoded.warnings.push("empty-sources")
    }
    if (sources.some((source) => isHttpSource(source))) {
      decoded.warnings.push("http-sources")
    }
    decoded.sources = sources.filter((source) => source.length > 0)
  }

  const insert = values.get("insert")
  if (insert !== undefined && insert !== "false") {
    decoded.warnings.push("invalid-insert")
  }

  const config = values.get("config")
  if (config !== undefined) {
    decoded.configUrl = config
  }

  const append = values.get("append_info")
  if (append === "false") {
    decoded.appendInfo = false
  } else if (append === "true" || append === undefined) {
    decoded.appendInfo = true
  } else {
    decoded.warnings.push("invalid-append-info")
    decoded.appendInfo = true
  }

  return decoded
}

export type SubGetHeaders = {
  skipped: SkipCounts | null
  filename: string | null
  exposed: { name: string; value: string }[]
}

export function filenameFromDisposition(header: string | null): string | null {
  if (header === null || header.length === 0) {
    return null
  }
  const quoted = /filename="([^"]+)"/i.exec(header)
  if (quoted) {
    return quoted[1]
  }
  const unquoted = /filename=([^;]+)/i.exec(header)
  if (unquoted) {
    return unquoted[1].trim()
  }
  return null
}

export function pickExposedHeaders(headers: {
  get: (name: string) => string | null
}): { name: string; value: string }[] {
  const picked: { name: string; value: string }[] = []
  for (const name of EXPOSED_HEADERS) {
    const value = headers.get(name)
    if (value !== null && value.length > 0) {
      picked.push({ name, value })
    }
  }
  return picked
}

export function readSubGetHeaders(
  headers: { get: (name: string) => string | null },
  target: Target
): SubGetHeaders {
  const exposed = pickExposedHeaders(headers)
  return {
    skipped: parseSkippedFromHeaders(exposed),
    filename:
      filenameFromDisposition(headers.get("content-disposition")) ??
      fallbackDownloadName(target),
    exposed,
  }
}
