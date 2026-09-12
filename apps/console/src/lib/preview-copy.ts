import { capabilityHint, knownErrorTitle, messages } from "./i18n.ts"
import type { Locale } from "./persist.ts"
import type { PreviewDone } from "./preview.ts"
import type { SkipCounts, SubscriptionUserInfo } from "./service-contract.ts"
import type { ClientTarget } from "./workshop.ts"

export type PreviewProfile = {
  error: { heading: string; wire: string | null } | null
  traffic?: { summary: string; expire?: string }
  skipped?: string
  omitted?: string
  capability?: string
}

export function formatByteCount(bytes: number, locale: Locale): string {
  const units =
    locale === "zh"
      ? (["字节", "KiB", "MiB", "GiB"] as const)
      : (["B", "KiB", "MiB", "GiB"] as const)
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  const digits = unit === 0 ? 0 : value >= 10 ? 1 : 2
  const number = unit === 0 ? String(bytes) : value.toFixed(digits)
  return `${number} ${units[unit]}`
}

function formatExpire(expire: number, locale: Locale): string {
  return new Date(expire * 1000).toLocaleDateString(
    locale === "zh" ? "zh-CN" : "en-US",
    { dateStyle: "medium" }
  )
}

export function trafficSummary(
  locale: Locale,
  traffic: SubscriptionUserInfo
): string {
  const copy = messages[locale]
  const used = formatByteCount(traffic.upload + traffic.download, locale)
  if (traffic.total > 0) {
    const cap = formatByteCount(traffic.total, locale)
    return locale === "zh"
      ? `已用 ${used}，共 ${cap}`
      : `${used} used of ${cap}`
  }
  return locale === "zh"
    ? `已用 ${used}（${copy.trafficNone}）`
    : `${used} used (${copy.trafficNone})`
}

export function expireSummary(locale: Locale, expire: number): string {
  const copy = messages[locale]
  return `${copy.expires} ${formatExpire(expire, locale)}`
}

/** Conversion re-emits expire=0. Date would render 1970. */
function datedExpire(expire: number | null): expire is number {
  return expire !== null && expire !== 0
}

export function skippedSummary(locale: Locale, counts: SkipCounts): string {
  const parts: string[] = []
  if (counts.parse > 0) {
    parts.push(
      locale === "zh"
        ? `${counts.parse} 个读不出来`
        : `${counts.parse} could not be read`
    )
  }
  if (counts.capability > 0) {
    parts.push(
      locale === "zh"
        ? `${counts.capability} 个这个客户端导不进去`
        : `${counts.capability} this client cannot import`
    )
  }
  if (counts.name > 0) {
    parts.push(
      locale === "zh"
        ? `${counts.name} 个名称无法保留`
        : `${counts.name} had a name this client cannot keep`
    )
  }
  const total = counts.parse + counts.capability + counts.name
  if (locale === "zh") {
    return `跳过 ${total} 个节点：${parts.join("，")}。`
  }
  const noun = total === 1 ? "node" : "nodes"
  return `Skipped ${total} ${noun}: ${parts.join(", ")}.`
}

export function omittedSummary(
  locale: Locale,
  omittedUrlRegex: number
): string {
  if (locale === "zh") {
    return `省略 ${omittedUrlRegex} 条 URL-REGEX 规则（这个客户端不支持）。`
  }
  return `Omitted ${omittedUrlRegex} URL-REGEX rules (this client cannot use them).`
}

function previewError(
  locale: Locale,
  preview: PreviewDone
): PreviewProfile["error"] {
  if (preview.kind.kind === "known-error") {
    return {
      heading: knownErrorTitle(locale, preview.kind.body),
      wire: preview.kind.body,
    }
  }
  if (preview.kind.kind !== "ok") {
    return {
      heading: `${messages[locale].status} ${preview.httpStatus}`,
      wire: null,
    }
  }
  return null
}

export function previewProfile(
  locale: Locale,
  preview: PreviewDone,
  target: ClientTarget
): PreviewProfile {
  return {
    error: previewError(locale, preview),
    traffic:
      preview.traffic === null
        ? undefined
        : {
            summary: trafficSummary(locale, preview.traffic),
            expire: datedExpire(preview.traffic.expire)
              ? expireSummary(locale, preview.traffic.expire)
              : undefined,
          },
    skipped:
      preview.skipped !== null
        ? skippedSummary(locale, preview.skipped)
        : undefined,
    omitted:
      preview.omitted !== null
        ? omittedSummary(locale, preview.omitted.omittedUrlRegex)
        : undefined,
    capability:
      preview.kind.kind === "ok" ||
      preview.skipped !== null ||
      preview.omitted !== null
        ? capabilityHint(locale, target)
        : undefined,
  }
}
