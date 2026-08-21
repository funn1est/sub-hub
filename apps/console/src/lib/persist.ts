import { MAX_SOURCES, isTarget, type Target } from "./service-contract.ts"

export const PERSIST_KEY = "sub-hub.console.v1"

export type Locale = "zh" | "en"
export type Theme = "system" | "light" | "dark"

/** Conversion fields the Workshop job assembles, pastes, and previews. */
export type WorkshopFields = {
  serviceOrigin: string
  accessToken: string
  sources: string[]
  target: Target
  configUrl: string
  appendInfo: boolean
}

/** Workshop conversion record plus Console chrome. */
export type PersistedWorkshop = WorkshopFields & {
  locale: Locale
  theme: Theme
}

export type ConsoleChrome = {
  locale: Locale
  theme: Theme
}

export function workshopFieldsOf(state: PersistedWorkshop): WorkshopFields {
  return {
    serviceOrigin: state.serviceOrigin,
    accessToken: state.accessToken,
    sources: state.sources,
    target: state.target,
    configUrl: state.configUrl,
    appendInfo: state.appendInfo,
  }
}

export function composePersisted(
  fields: WorkshopFields,
  chrome: ConsoleChrome
): PersistedWorkshop {
  return {
    ...fields,
    locale: chrome.locale,
    theme: chrome.theme,
  }
}

type StorageLike = {
  getItem: (key: string) => string | null
  setItem?: (key: string, value: string) => void
}

const THEMES: readonly Theme[] = ["system", "light", "dark"]

export function defaultLocale(language: string): Locale {
  return language.toLowerCase().startsWith("zh") ? "zh" : "en"
}

export function defaultPersisted(
  overrides: Partial<PersistedWorkshop> = {}
): PersistedWorkshop {
  return {
    locale: "en",
    theme: "system",
    serviceOrigin: "",
    accessToken: "",
    sources: [""],
    target: "clash",
    configUrl: "",
    appendInfo: true,
    ...overrides,
  }
}

export function serializePersisted(state: PersistedWorkshop): string {
  const body: PersistedWorkshop = {
    locale: state.locale,
    theme: state.theme,
    serviceOrigin: state.serviceOrigin,
    accessToken: state.accessToken,
    sources: state.sources.slice(0, MAX_SOURCES),
    target: state.target,
    configUrl: state.configUrl,
    appendInfo: state.appendInfo,
  }
  return JSON.stringify(body)
}

export function parsePersisted(
  raw: string | null,
  fallback: Partial<PersistedWorkshop> = {}
): PersistedWorkshop {
  const defaults = defaultPersisted(fallback)
  if (raw === null) {
    return defaults
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return defaults
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return defaults
  }

  const value = parsed as Record<string, unknown>
  const sources = Array.isArray(value.sources)
    ? value.sources
        .filter((item): item is string => typeof item === "string")
        .slice(0, MAX_SOURCES)
    : defaults.sources

  return {
    locale:
      value.locale === "zh" || value.locale === "en"
        ? value.locale
        : defaults.locale,
    theme: isTheme(value.theme) ? value.theme : defaults.theme,
    serviceOrigin:
      typeof value.serviceOrigin === "string"
        ? value.serviceOrigin
        : defaults.serviceOrigin,
    accessToken:
      typeof value.accessToken === "string"
        ? value.accessToken
        : defaults.accessToken,
    sources: sources.length > 0 ? sources : [""],
    target:
      typeof value.target === "string" && isTarget(value.target)
        ? value.target
        : defaults.target,
    configUrl:
      typeof value.configUrl === "string"
        ? value.configUrl
        : defaults.configUrl,
    appendInfo:
      typeof value.appendInfo === "boolean"
        ? value.appendInfo
        : defaults.appendInfo,
  }
}

export function loadPersisted(
  storage: StorageLike,
  fallback: Partial<PersistedWorkshop> = {}
): PersistedWorkshop {
  return parsePersisted(storage.getItem(PERSIST_KEY), fallback)
}

export function savePersisted(
  storage: StorageLike,
  state: PersistedWorkshop
): void {
  storage.setItem?.(PERSIST_KEY, serializePersisted(state))
}

function isTheme(value: unknown): value is Theme {
  return (
    typeof value === "string" && (THEMES as readonly string[]).includes(value)
  )
}
