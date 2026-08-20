/**
 * GET Conversion Service contract used by the Workshop.
 *
 * HTTP (`sub-hub-http`) is the authority. This module is a handwritten adapter
 * so Workshop URL assembly does not own error bodies, skip grammar, or wire
 * tokens. Do not generate TypeScript from Rust DTOs (ADR-0020 is retired).
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

export const EXPOSED_HEADERS = [
  "content-disposition",
  "profile-update-interval",
  "subscription-userinfo",
  "x-subconverter-result",
  "x-subconverter-omitted-rules",
  "x-subconverter-skipped",
] as const

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

export type SubscriptionAssemblyInput = {
  serviceOrigin: string
  accessToken: string
  sources: string[]
  target: Target
  configUrl: string
  appendInfo: boolean
}

export type Assembled = {
  url: string | null
  getTarget: string | null
  overLimit: boolean
}

export type AccessTokenParse = { ok: true; token: string } | { ok: false }

export type PasteWarning =
  | "unknown-keys"
  | "duplicate-keys"
  | "invalid-target"
  | "invalid-token"
  | "invalid-append-info"

export type PasteResult =
  | {
      ok: true
      workshop: Partial<SubscriptionAssemblyInput>
      warnings: PasteWarning[]
    }
  | { ok: false; reason: "invalid-url" }

export function parseServiceOrigin(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed.length === 0) {
    return null
  }

  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return null
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null
  }
  if (url.username !== "" || url.password !== "") {
    return null
  }
  if (url.search !== "" || url.hash !== "") {
    return null
  }
  if (url.pathname !== "" && url.pathname !== "/") {
    return null
  }

  return url.origin
}

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

export function parseHttpsResourceUrl(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed.length === 0) {
    return null
  }

  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return null
  }

  if (url.protocol !== "https:") {
    return null
  }
  if (url.username !== "" || url.password !== "") {
    return null
  }
  if (url.hash !== "") {
    return null
  }
  return url.href
}

export function nonemptySources(sources: readonly string[]): string[] {
  return sources
    .map((source) => source.trim())
    .filter((source) => source.length > 0)
}

export function assembleSubscription(
  input: SubscriptionAssemblyInput
): Assembled {
  const origin = parseServiceOrigin(input.serviceOrigin)
  const token = parseAccessToken(input.accessToken)
  const sources = nonemptySources(input.sources)
  const config = input.configUrl.trim()

  if (
    origin === null ||
    !token.ok ||
    sources.length === 0 ||
    sources.length > MAX_SOURCES ||
    sources.some((source) => source.includes("|")) ||
    !isTarget(input.target) ||
    (config.length > 0 && parseHttpsResourceUrl(config) === null)
  ) {
    return { url: null, getTarget: null, overLimit: false }
  }

  const path = token.token.length > 0 ? `/sub/${token.token}` : "/sub"
  const queryParts = [
    `target=${input.target}`,
    `url=${encodeURIComponent(sources.join("|"))}`,
  ]
  if (config.length > 0) {
    queryParts.push(`config=${encodeURIComponent(config)}`)
  }
  if (!input.appendInfo) {
    queryParts.push("append_info=false")
  }

  const getTarget = `${path}?${queryParts.join("&")}`
  return {
    url: `${origin}${getTarget}`,
    getTarget,
    overLimit:
      new TextEncoder().encode(getTarget).length >= GET_TARGET_LIMIT_BYTES,
  }
}

export function parseSubscriptionUrl(raw: string): PasteResult {
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

  const origin = parseServiceOrigin(url.origin)
  if (origin === null) {
    return { ok: false, reason: "invalid-url" }
  }

  const pathname = url.pathname.replace(/\/+$/, "") || "/"
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

  const keys = [...url.searchParams.keys()]
  const seen = new Set<string>()
  let unknown = false
  let duplicate = false
  for (const key of keys) {
    if (!isQueryKey(key)) {
      unknown = true
    }
    if (seen.has(key)) {
      duplicate = true
    }
    seen.add(key)
  }
  if (unknown) {
    warnings.push("unknown-keys")
  }
  if (duplicate) {
    warnings.push("duplicate-keys")
  }

  const workshop: Partial<SubscriptionAssemblyInput> = {
    serviceOrigin: origin,
    accessToken,
    configUrl: "",
    appendInfo: true,
  }

  const target = url.searchParams.get("target")
  if (target !== null) {
    if (isTarget(target)) {
      workshop.target = target
    } else {
      warnings.push("invalid-target")
    }
  }

  const urlParam = url.searchParams.get("url")
  if (urlParam !== null && urlParam.length > 0) {
    workshop.sources = urlParam.split("|")
  }

  const config = url.searchParams.get("config")
  if (config !== null) {
    workshop.configUrl = config
  }

  const append = url.searchParams.get("append_info")
  if (append === "false") {
    workshop.appendInfo = false
  } else if (append === "true" || append === null) {
    workshop.appendInfo = true
  } else {
    warnings.push("invalid-append-info")
    workshop.appendInfo = true
  }

  return { ok: true, workshop, warnings }
}
