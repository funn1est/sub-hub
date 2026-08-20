import {
  EXPOSED_HEADERS,
  VERSION_BODY,
  isKnownServiceError,
  type KnownServiceError,
} from "./service-contract.ts"
import { isLoopbackHost } from "./workshop.ts"

export {
  VERSION_BODY,
  fallbackDownloadName,
  parseSkippedHeader,
  type SkipCounts,
} from "./service-contract.ts"

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

export function pickExposedHeaders(
  headers: Headers
): { name: string; value: string }[] {
  const picked: { name: string; value: string }[] = []
  for (const name of EXPOSED_HEADERS) {
    const value = headers.get(name)
    if (value !== null && value.length > 0) {
      picked.push({ name, value })
    }
  }
  return picked
}
