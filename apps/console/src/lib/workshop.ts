import {
  GET_TARGET_LIMIT_BYTES,
  MAX_SOURCES,
  encodeSubGetTarget,
  isHttpSource,
  isQueryKey,
  isTarget,
  parseAccessToken,
  percentDecodeValue,
  type Target,
} from "./service-contract.ts"
import type { PersistedWorkshop, WorkshopFields } from "./persist.ts"

export {
  runPreview,
  runVersionProbe,
  type PreviewState,
  type VersionProbe,
} from "./preview.ts"

/** GET document media type for a Preview download. */
export { subscriptionMediaType as previewMediaType } from "./service-contract.ts"

export function clashInstallUrl(subscriptionUrl: string): string {
  return `clash://install-config?url=${encodeURIComponent(subscriptionUrl)}`
}

export type SubscriptionAssemblyInput = WorkshopFields

export type Assembled = {
  url: string | null
  getTarget: string | null
  overLimit: boolean
  previewable: boolean
  clashInstall: boolean
}

export type WorkshopView = {
  assembled: Assembled
  originInvalid: boolean
  tokenInvalid: boolean
  configInvalid: boolean
  sourceInvalid: boolean[]
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

function nonemptySources(sources: readonly string[]): string[] {
  return sources
    .map((source) => source.trim())
    .filter((source) => source.length > 0)
}

function sourceRowInvalid(source: string): boolean {
  return source.includes("|") || isHttpSource(source.trim())
}

const emptyAssembled: Assembled = {
  url: null,
  getTarget: null,
  overLimit: false,
  previewable: false,
  clashInstall: false,
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
    sources.some((source) => source.includes("|") || isHttpSource(source)) ||
    !isTarget(input.target) ||
    (config.length > 0 && parseHttpsResourceUrl(config) === null)
  ) {
    return emptyAssembled
  }

  const getTarget = encodeSubGetTarget({
    accessToken: token.token,
    target: input.target,
    sources,
    configUrl: config,
    appendInfo: input.appendInfo,
  })
  const overLimit =
    new TextEncoder().encode(getTarget).length > GET_TARGET_LIMIT_BYTES
  return {
    url: `${origin}${getTarget}`,
    getTarget,
    overLimit,
    previewable: !overLimit,
    clashInstall: input.target === "clash" || input.target === "mihomo",
  }
}

/** Field chrome and assemble share one Workshop job diagnosis. */
export function evaluateWorkshop(input: WorkshopFields): WorkshopView {
  return {
    assembled: assembleSubscription(input),
    originInvalid:
      input.serviceOrigin.trim().length > 0 &&
      parseServiceOrigin(input.serviceOrigin) === null,
    tokenInvalid: !parseAccessToken(input.accessToken).ok,
    configInvalid:
      input.configUrl.trim().length > 0 &&
      parseHttpsResourceUrl(input.configUrl) === null,
    sourceInvalid: input.sources.map(sourceRowInvalid),
  }
}

type PasteDecode =
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

/** Lenient Subscription URL salvage for Workshop paste. Unknown keys warn. */
function decodeSubscriptionUrl(raw: string): PasteDecode {
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
  const decoded: Extract<PasteDecode, { ok: true }> = {
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

export function parseSubscriptionUrl(raw: string): PasteResult {
  const decoded = decodeSubscriptionUrl(raw)
  if (!decoded.ok) {
    return decoded
  }
  const origin = parseServiceOrigin(decoded.origin)
  if (origin === null) {
    return { ok: false, reason: "invalid-url" }
  }
  return {
    ok: true,
    workshop: {
      serviceOrigin: origin,
      accessToken: decoded.accessToken,
      sources: decoded.sources,
      target: decoded.target,
      configUrl: decoded.configUrl,
      appendInfo: decoded.appendInfo,
    },
    warnings: decoded.warnings,
  }
}

export function applyPaste(
  state: PersistedWorkshop,
  parsed: Extract<PasteResult, { ok: true }>
): PersistedWorkshop {
  return {
    ...state,
    serviceOrigin: parsed.workshop.serviceOrigin ?? state.serviceOrigin,
    accessToken: parsed.workshop.accessToken ?? state.accessToken,
    sources: parsed.workshop.sources ?? state.sources,
    target: parsed.workshop.target ?? state.target,
    configUrl: parsed.workshop.configUrl ?? state.configUrl,
    appendInfo: parsed.workshop.appendInfo ?? state.appendInfo,
  }
}

function looksLikeAssembledSubscription(
  workshop: Partial<SubscriptionAssemblyInput>
): boolean {
  return (
    (workshop.accessToken?.length ?? 0) > 0 ||
    workshop.target !== undefined ||
    (workshop.sources?.length ?? 0) > 0 ||
    (workshop.configUrl?.length ?? 0) > 0 ||
    workshop.appendInfo === false
  )
}

/**
 * True when pasted text is a Conversion Service Subscription URL, not a
 * provider `https://…/sub?token=` source.
 */
export function subscriptionPasteFrom(
  raw: string
): Extract<PasteResult, { ok: true }> | null {
  const parsed = parseSubscriptionUrl(raw)
  if (!parsed.ok || !looksLikeAssembledSubscription(parsed.workshop)) {
    return null
  }
  return parsed
}
