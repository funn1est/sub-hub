/**
 * GET Conversion Service contract used by the Workshop.
 *
 * HTTP (`sub-hub-http`) is the authority. This module is a handwritten adapter
 * so Workshop URL assembly does not own error bodies, skip grammar, or wire
 * tokens. Do not generate TypeScript from Rust DTOs (ADR-0020 is retired).
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

export const QUERY_KEYS = ["target", "url", "config", "append_info"] as const

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
