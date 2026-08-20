import {
  GET_TARGET_LIMIT_BYTES,
  MAX_SOURCES,
  decodeSubGetTarget,
  encodeSubGetTarget,
  isTarget,
  parseAccessToken,
  type PasteWarning,
  type Target,
} from "./service-contract.ts"
import type { PersistedWorkshop } from "./persist.ts"

export {
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  ACL4SSR_ONLINE_URL,
  acl4ssrConfigLabel,
  acl4ssrConfigUrl,
  configPresetOf,
  configSelectionId,
  type Acl4ssrConfigFile,
  type ConfigPreset,
} from "./acl4ssr-catalog.ts"

export function clashInstallUrl(subscriptionUrl: string): string {
  return `clash://install-config?url=${encodeURIComponent(subscriptionUrl)}`
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

export type { PasteWarning } from "./service-contract.ts"

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

  const getTarget = encodeSubGetTarget({
    accessToken: token.token,
    target: input.target,
    sources,
    configUrl: config,
    appendInfo: input.appendInfo,
  })
  return {
    url: `${origin}${getTarget}`,
    getTarget,
    overLimit:
      new TextEncoder().encode(getTarget).length > GET_TARGET_LIMIT_BYTES,
  }
}

export function parseSubscriptionUrl(raw: string): PasteResult {
  const decoded = decodeSubGetTarget(raw)
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

export function canPreview(assembled: Assembled): boolean {
  return assembled.url !== null && !assembled.overLimit
}

export function showsClashInstall(
  assembled: Assembled,
  target: Target
): boolean {
  return assembled.url !== null && (target === "clash" || target === "mihomo")
}
