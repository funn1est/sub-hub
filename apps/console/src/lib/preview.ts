import {
  EXPOSED_HEADERS,
  SKIPPED_HEADER,
  VERSION_BODY,
  VERSION_PATH,
  fallbackDownloadName,
  isKnownServiceError,
  parseOmittedRulesHeader,
  parseSkippedHeader,
  type KnownServiceError,
  type OmittedRules,
  type SkipCounts,
  type Target,
} from "./service-contract.ts"

export {
  VERSION_BODY,
  fallbackDownloadName,
  parseOmittedRulesHeader,
  parseSkippedHeader,
  type OmittedRules,
  type SkipCounts,
} from "./service-contract.ts"

export function parseSkippedFromHeaders(
  headers: readonly { name: string; value: string }[]
): SkipCounts | null {
  const value =
    headers.find((header) => header.name === SKIPPED_HEADER)?.value ?? null
  return parseSkippedHeader(value)
}

export type SubGetHeaders = {
  skipped: SkipCounts | null
  omitted: OmittedRules | null
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

function pickExposedHeaders(headers: {
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
    omitted: parseOmittedRulesHeader(
      headers.get("x-subconverter-result"),
      headers.get("x-subconverter-omitted-rules")
    ),
    filename:
      filenameFromDisposition(headers.get("content-disposition")) ??
      fallbackDownloadName(target),
    exposed,
  }
}

export const PREVIEW_VIEW_LIMIT_BYTES = 256 * 1024

export type VersionKind = "sub-hub" | "other"
export type FetchFailure = "mixed-content" | "local-network" | "cors-or-network"
export type PreviewBodyKind =
  | { kind: "ok" }
  | { kind: "known-error"; body: KnownServiceError }
  | { kind: "http" }

export function classifyVersionBody(body: string): VersionKind {
  return VERSION_BODY.test(body.trim()) ? "sub-hub" : "other"
}

export function classifyPreviewBody(
  status: number,
  body: string
): PreviewBodyKind {
  if (isKnownServiceError(body)) {
    return { kind: "known-error", body }
  }
  if (status === 200) {
    return { kind: "ok" }
  }
  return { kind: "http" }
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

export function classifyFetchFailure(input: {
  pageHttps: boolean
  serviceOrigin: string
}): FetchFailure {
  let url: URL
  try {
    url = new URL(input.serviceOrigin)
  } catch {
    return "cors-or-network"
  }

  if (input.pageHttps && url.protocol === "http:") {
    return isLoopbackHost(url.hostname) ? "local-network" : "mixed-content"
  }
  return "cors-or-network"
}

export type VersionProbe =
  | { status: "ok"; body: string }
  | { status: "other" }
  | { status: "unreachable" }

export type VersionState =
  { status: "idle" } | { status: "checking" } | VersionProbe

export async function runVersionProbe(input: {
  origin: string
  signal?: AbortSignal
  fetchImpl?: (
    url: string,
    init?: { signal?: AbortSignal }
  ) => Promise<{ text: () => Promise<string> }>
}): Promise<VersionProbe> {
  try {
    const response = await (input.fetchImpl ?? fetch)(
      `${input.origin}${VERSION_PATH}`,
      { signal: input.signal }
    )
    const body = await response.text()
    if (input.signal?.aborted) {
      return { status: "unreachable" }
    }
    if (classifyVersionBody(body) === "sub-hub") {
      return { status: "ok", body: body.trim() }
    }
    return { status: "other" }
  } catch {
    return { status: "unreachable" }
  }
}

export function truncatePreviewBody(body: string): {
  text: string
  truncated: boolean
} {
  const bytes = new TextEncoder().encode(body)
  if (bytes.length <= PREVIEW_VIEW_LIMIT_BYTES) {
    return { text: body, truncated: false }
  }
  return {
    text: new TextDecoder("utf-8", { fatal: false }).decode(
      bytes.subarray(0, PREVIEW_VIEW_LIMIT_BYTES)
    ),
    truncated: true,
  }
}

export type PreviewDone = {
  status: "done"
  httpStatus: number
  kind: PreviewBodyKind
  headers: { name: string; value: string }[]
  skipped: SkipCounts | null
  omitted: OmittedRules | null
  body: string
  viewText: string
  truncated: boolean
  filename: string
}

export type PreviewOutcome =
  PreviewDone | { status: "unreachable"; cause: FetchFailure }

export type PreviewState =
  { status: "idle" } | { status: "loading" } | PreviewOutcome

export type PreviewFetch = (url: string) => Promise<{
  status: number
  text: () => Promise<string>
  headers: { get: (name: string) => string | null }
}>

export async function runPreview(input: {
  url: string
  target: Target
  pageHttps: boolean
  fetchImpl?: PreviewFetch
}): Promise<PreviewOutcome> {
  const fetchImpl = input.fetchImpl ?? fetch
  try {
    const response = await fetchImpl(input.url)
    const body = await response.text()
    const truncated = truncatePreviewBody(body)
    const headers = readSubGetHeaders(response.headers, input.target)
    return {
      status: "done",
      httpStatus: response.status,
      kind: classifyPreviewBody(response.status, body),
      headers: headers.exposed,
      skipped: headers.skipped,
      omitted: headers.omitted,
      body,
      viewText: truncated.text,
      truncated: truncated.truncated,
      filename: headers.filename ?? "",
    }
  } catch {
    let serviceOrigin: string
    try {
      serviceOrigin = new URL(input.url).origin
    } catch {
      serviceOrigin = input.url
    }
    return {
      status: "unreachable",
      cause: classifyFetchFailure({
        pageHttps: input.pageHttps,
        serviceOrigin,
      }),
    }
  }
}
