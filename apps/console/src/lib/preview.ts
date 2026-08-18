import {
  EXPOSED_HEADERS,
  isKnownServiceError,
  isLoopbackHost,
  type KnownServiceError,
  type Target,
} from "./workshop.ts"

export const PREVIEW_VIEW_LIMIT_BYTES = 256 * 1024
export const VERSION_BODY = /^sub-hub v\d+\.\d+\.\d+ backend$/

export type VersionKind = "sub-hub" | "other"
export type FetchFailure = "mixed-content" | "local-network" | "cors-or-network"
export type PreviewBodyKind =
  | { kind: "ok" }
  | { kind: "known-error"; body: KnownServiceError }
  | { kind: "http" }

export function classifyVersionBody(body: string): VersionKind {
  return VERSION_BODY.test(body.trim()) ? "sub-hub" : "other"
}

export function classifyPreviewBody(status: number, body: string): PreviewBodyKind {
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

export function truncatePreviewBody(body: string): { text: string; truncated: boolean } {
  const bytes = new TextEncoder().encode(body)
  if (bytes.length <= PREVIEW_VIEW_LIMIT_BYTES) {
    return { text: body, truncated: false }
  }
  return {
    text: new TextDecoder("utf-8", { fatal: false }).decode(
      bytes.subarray(0, PREVIEW_VIEW_LIMIT_BYTES),
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

export function fallbackDownloadName(target: Target): string {
  switch (target) {
    case "clash":
      return "sub-hub-clash.yaml"
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

export function pickExposedHeaders(headers: Headers): { name: string; value: string }[] {
  const picked: { name: string; value: string }[] = []
  for (const name of EXPOSED_HEADERS) {
    const value = headers.get(name)
    if (value !== null && value.length > 0) {
      picked.push({ name, value })
    }
  }
  return picked
}
