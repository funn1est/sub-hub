import { describe, expect, it } from "vitest"

import { KNOWN_SERVICE_ERRORS } from "./service-contract.ts"
import { knownErrorTitle, messages, skippedSummary } from "./i18n.ts"

describe("known Conversion Service errors", () => {
  it("has a distinct zh and en title for every exact English body", () => {
    expect(KNOWN_SERVICE_ERRORS).toEqual([
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
    ])

    for (const body of KNOWN_SERVICE_ERRORS) {
      const zh = knownErrorTitle("zh", body)
      const en = knownErrorTitle("en", body)
      expect(zh.length).toBeGreaterThan(0)
      expect(en.length).toBeGreaterThan(0)
      expect(zh).not.toBe(en)
      expect(zh).not.toBe(body)
    }
  })
})

describe("append_info copy", () => {
  it("describes subscription-userinfo capture, not profile-update-interval control", () => {
    expect(messages.en.appendInfo).toContain("subscription-userinfo")
    expect(messages.en.appendInfo).not.toBe("Append profile-update-interval")
    expect(messages.en.appendInfoHint).toContain("append_info=false")
    expect(messages.en.appendInfoHint).toContain("profile-update-interval: 24")
    expect(messages.zh.appendInfo).toContain("subscription-userinfo")
    expect(messages.zh.appendInfoHint).toContain("append_info=false")
  })
})

describe("skippedSummary", () => {
  it("lists only the non-zero buckets in zh and en", () => {
    expect(skippedSummary("en", { parse: 1, capability: 4, name: 0 })).toBe(
      "Skipped 5 nodes (1 could not be parsed, 4 unsupported on this target)."
    )
    expect(skippedSummary("zh", { parse: 1, capability: 4, name: 0 })).toBe(
      "跳过 5 个节点（解析失败 1，此 target 不支持 4）。"
    )
  })
})
