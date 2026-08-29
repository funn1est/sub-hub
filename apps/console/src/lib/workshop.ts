import {
  GET_TARGET_LIMIT_BYTES,
  TARGETS,
  encodeSubGetTarget,
  isHttpSource,
  parseAccessToken,
  type Target,
} from "./service-contract.ts"

/** Conversion fields the Workshop job assembles and previews. */
export type WorkshopFields = {
  serviceOrigin: string
  accessToken: string
  sources: string[]
  target: Target
  configUrl: string
  appendInfo: boolean
  /** When true, Subscription URL includes expand=true (inline remotes). */
  expand: boolean
}

/** Shared input attrs for origin / source / config URL fields. */
export const urlField = {
  inputMode: "url" as const,
  autoCapitalize: "none" as const,
  autoCorrect: "off" as const,
  spellCheck: false,
}

/** Injected Workshop fetch port. Preview, version-probe, and session share it. */
export type WorkshopFetch = (
  url: string,
  init?: { signal?: AbortSignal }
) => Promise<{
  status: number
  text: () => Promise<string>
  headers: { get: (name: string) => string | null }
}>

export function clashInstallUrl(subscriptionUrl: string): string {
  return `clash://install-config?url=${encodeURIComponent(subscriptionUrl)}`
}

export function surgeInstallUrl(subscriptionUrl: string): string {
  return `surge:///install-config?url=${encodeURIComponent(subscriptionUrl)}`
}

export type AssembledTarget = {
  target: Target
  url: string
  getTarget: string
  overLimit: boolean
}

export type Assembled = {
  url: string | null
  getTarget: string | null
  overLimit: boolean
  previewable: boolean
  clashInstall: boolean
  surgeInstall: boolean
  siblings: AssembledTarget[]
}

export type WorkshopView = {
  assembled: Assembled
  canonicalOrigin: string | null
  originInvalid: boolean
  tokenInvalid: boolean
  configInvalid: boolean
  sourceInvalid: boolean[]
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
  surgeInstall: false,
  siblings: [],
}

/** Field chrome and assemble share one Workshop job diagnosis. */
export function evaluateWorkshop(input: WorkshopFields): WorkshopView {
  const origin = parseServiceOrigin(input.serviceOrigin)
  const token = parseAccessToken(input.accessToken)
  const sources = nonemptySources(input.sources)
  const config = input.configUrl.trim()
  const originInvalid = input.serviceOrigin.trim().length > 0 && origin === null
  const tokenInvalid = !token.ok
  const configInvalid =
    config.length > 0 && parseHttpsResourceUrl(config) === null
  const sourceInvalid = input.sources.map(sourceRowInvalid)
  const sourcesOk =
    sources.length > 0 &&
    !sources.some((source) => source.includes("|") || isHttpSource(source))
  const assembled =
    origin !== null && token.ok && sourcesOk && !configInvalid
      ? assembledFrom({
          origin,
          token: token.token,
          sources,
          target: input.target,
          configUrl: config,
          appendInfo: input.appendInfo,
          expand: input.expand,
        })
      : emptyAssembled
  return {
    assembled,
    canonicalOrigin: origin,
    originInvalid,
    tokenInvalid,
    configInvalid,
    sourceInvalid,
  }
}

function assembledFrom(input: {
  origin: string
  token: string
  sources: string[]
  target: Target
  configUrl: string
  appendInfo: boolean
  expand: boolean
}): Assembled {
  const siblings = TARGETS.map((target) => {
    const getTarget = encodeSubGetTarget({
      accessToken: input.token,
      target,
      sources: input.sources,
      configUrl: input.configUrl,
      appendInfo: input.appendInfo,
      expand: input.expand,
    })
    return {
      target,
      url: `${input.origin}${getTarget}`,
      getTarget,
      overLimit:
        new TextEncoder().encode(getTarget).length > GET_TARGET_LIMIT_BYTES,
    }
  })
  const primary =
    siblings.find((sibling) => sibling.target === input.target) ?? siblings[0]
  if (primary === undefined) {
    return emptyAssembled
  }
  return {
    url: primary.url,
    getTarget: primary.getTarget,
    overLimit: primary.overLimit,
    previewable: !primary.overLimit,
    clashInstall: input.target === "clash" || input.target === "mihomo",
    surgeInstall: input.target === "surge",
    siblings,
  }
}
