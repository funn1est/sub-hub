export const TARGETS = [
  "clash",
  "mihomo",
  "quanx",
  "singbox",
  "loon",
  "egern",
] as const

export type Target = (typeof TARGETS)[number]

export const ACL4SSR_ONLINE_FILES = [
  "ACL4SSR_Online.ini",
  "ACL4SSR_Online_AdblockPlus.ini",
  "ACL4SSR_Online_MultiCountry.ini",
  "ACL4SSR_Online_NoAuto.ini",
  "ACL4SSR_Online_NoReject.ini",
] as const

export const ACL4SSR_MINI_FILES = [
  "ACL4SSR_Online_Mini.ini",
  "ACL4SSR_Online_Mini_AdblockPlus.ini",
  "ACL4SSR_Online_Mini_Ai.ini",
  "ACL4SSR_Online_Mini_Fallback.ini",
  "ACL4SSR_Online_Mini_MultiCountry.ini",
  "ACL4SSR_Online_Mini_MultiMode.ini",
  "ACL4SSR_Online_Mini_NoAuto.ini",
] as const

export const ACL4SSR_FULL_FILES = [
  "ACL4SSR_Online_Full.ini",
  "ACL4SSR_Online_Full_AdblockPlus.ini",
  "ACL4SSR_Online_Full_Google.ini",
  "ACL4SSR_Online_Full_MultiMode.ini",
  "ACL4SSR_Online_Full_Netflix.ini",
  "ACL4SSR_Online_Full_NoAuto.ini",
] as const

export type Acl4ssrConfigFile =
  | (typeof ACL4SSR_ONLINE_FILES)[number]
  | (typeof ACL4SSR_MINI_FILES)[number]
  | (typeof ACL4SSR_FULL_FILES)[number]

export type ConfigPreset =
  | { kind: "none" }
  | { kind: "online"; file: (typeof ACL4SSR_ONLINE_FILES)[number] }
  | { kind: "mini"; file: (typeof ACL4SSR_MINI_FILES)[number] }
  | { kind: "full"; file: (typeof ACL4SSR_FULL_FILES)[number] }
  | { kind: "custom" }

export function acl4ssrConfigUrl(file: Acl4ssrConfigFile): string {
  return `https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/${file}`
}

export function acl4ssrConfigLabel(file: Acl4ssrConfigFile): string {
  return file.endsWith(".ini") ? file.slice(0, -".ini".length) : file
}

export const ACL4SSR_ONLINE_URL = acl4ssrConfigUrl("ACL4SSR_Online.ini")

const ACL4SSR_PRESET_BY_URL = new Map<
  string,
  Exclude<ConfigPreset, { kind: "none" } | { kind: "custom" }>
>()
for (const file of ACL4SSR_ONLINE_FILES) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(file), { kind: "online", file })
}
for (const file of ACL4SSR_MINI_FILES) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(file), { kind: "mini", file })
}
for (const file of ACL4SSR_FULL_FILES) {
  ACL4SSR_PRESET_BY_URL.set(acl4ssrConfigUrl(file), { kind: "full", file })
}

export const MAX_SOURCES = 5
export const GET_TARGET_LIMIT_BYTES = 8192

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

export const EXPOSED_HEADERS = [
  "content-disposition",
  "profile-update-interval",
  "subscription-userinfo",
  "x-subconverter-result",
  "x-subconverter-omitted-rules",
  "x-subconverter-skipped",
] as const

export type WorkshopInput = {
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
  | { ok: true; workshop: Partial<WorkshopInput>; warnings: PasteWarning[] }
  | { ok: false; reason: "invalid-url" }

const KNOWN_QUERY_KEYS = new Set(["target", "url", "config", "append_info"])

export function isTarget(value: string): value is Target {
  return (TARGETS as readonly string[]).includes(value)
}

export function isKnownServiceError(body: string): body is KnownServiceError {
  return KNOWN_ERROR_SET.has(body)
}

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

export function assembleSubscription(input: WorkshopInput): Assembled {
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
    if (!KNOWN_QUERY_KEYS.has(key)) {
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

  const workshop: Partial<WorkshopInput> = {
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

export function clashInstallUrl(subscriptionUrl: string): string {
  return `clash://install-config?url=${encodeURIComponent(subscriptionUrl)}`
}

export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase()
  if (host === "localhost" || host.endsWith(".localhost")) {
    return true
  }
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") {
    return true
  }
  return /^127(?:\.\d{1,3}){3}$/.test(host)
}

export function configPresetOf(configUrl: string): ConfigPreset {
  const trimmed = configUrl.trim()
  if (trimmed.length === 0) {
    return { kind: "none" }
  }
  return ACL4SSR_PRESET_BY_URL.get(trimmed) ?? { kind: "custom" }
}
