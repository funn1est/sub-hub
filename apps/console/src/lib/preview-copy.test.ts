import { describe, expect, it } from "vitest"

import { messages } from "./i18n.ts"
import {
  formatByteCount,
  omittedSummary,
  previewProfile,
  skippedSummary,
  trafficSummary,
} from "./preview-copy.ts"
import type { PreviewDone } from "./preview.ts"

function done(
  partial: Partial<PreviewDone> & Pick<PreviewDone, "body">
): PreviewDone {
  return {
    status: "done",
    httpStatus: 200,
    kind: { kind: "ok" },
    headers: [],
    skipped: null,
    omitted: null,
    traffic: null,
    viewText: partial.body,
    truncated: false,
    filename: "sub-hub-mihomo.yaml",
    ...partial,
  }
}

describe("formatByteCount", () => {
  it("uses binary units", () => {
    expect(formatByteCount(512, "en")).toBe("512 B")
    expect(formatByteCount(512, "zh")).toBe("512 字节")
    expect(formatByteCount(1536, "en")).toBe("1.50 KiB")
    expect(formatByteCount(10 * 1024 * 1024, "en")).toBe("10.0 MiB")
  })
})

describe("skippedSummary", () => {
  it("lists only the non-zero buckets in zh and en", () => {
    expect(skippedSummary("en", { parse: 1, capability: 4, name: 0 })).toBe(
      "Skipped 5 nodes: 1 could not be read, 4 this client cannot import."
    )
    expect(skippedSummary("en", { parse: 0, capability: 1, name: 0 })).toBe(
      "Skipped 1 node: 1 this client cannot import."
    )
    expect(skippedSummary("zh", { parse: 1, capability: 4, name: 0 })).toBe(
      "跳过 5 个节点：1 个读不出来，4 个这个客户端导不进去。"
    )
  })
})

describe("omittedSummary", () => {
  it("names the omitted URL-REGEX count in zh and en", () => {
    expect(omittedSummary("en", 3)).toBe(
      "Omitted 3 URL-REGEX rules (this client cannot use them)."
    )
    expect(omittedSummary("zh", 3)).toBe(
      "省略 3 条 URL-REGEX 规则（这个客户端不支持）。"
    )
  })
})

describe("preview profile card copy", () => {
  it("summarizes traffic from the GET record without a second URL", () => {
    expect(
      trafficSummary("en", {
        upload: 1024,
        download: 1024,
        total: 10 * 1024 * 1024,
        expire: null,
      })
    ).toBe("2.00 KiB used of 10.0 MiB")
    expect(
      trafficSummary("zh", {
        upload: 512,
        download: 0,
        total: 0,
        expire: null,
      })
    ).toContain(messages.zh.trafficNone)
  })
})

describe("previewProfile", () => {
  it("reads traffic from the GET record and keeps capability on ok", () => {
    const profile = previewProfile(
      "en",
      done({
        body: "mode: rule\n",
        traffic: {
          upload: 1024,
          download: 1024,
          total: 10 * 1024 * 1024,
          expire: null,
        },
      }),
      "clash"
    )
    expect(profile.error).toBeNull()
    expect(profile.traffic?.summary).toBe("2.00 KiB used of 10.0 MiB")
    expect(profile.traffic?.expire).toBeUndefined()
    expect(profile.capability).toMatch(/Clash-family/)
  })

  it("nests a dated expire under traffic", () => {
    const profile = previewProfile(
      "en",
      done({
        body: "mode: rule\n",
        traffic: {
          upload: 1,
          download: 2,
          total: 3,
          expire: 1_893_456_000,
        },
      }),
      "clash"
    )
    expect(profile.error).toBeNull()
    expect(profile.traffic?.expire).toMatch(/^Expires /)
  })

  it("omits a date when Conversion re-emits expire=0", () => {
    const profile = previewProfile(
      "en",
      done({
        body: "mode: rule\n",
        traffic: {
          upload: 1,
          download: 2,
          total: 3,
          expire: 0,
        },
      }),
      "clash"
    )
    expect(profile.error).toBeNull()
    expect(profile.traffic?.summary).toBe("3 B used of 3 B")
    expect(profile.traffic?.expire).toBeUndefined()
  })

  it("omits traffic when the GET has no subscription-userinfo", () => {
    const profile = previewProfile(
      "en",
      done({ body: "mode: rule\n" }),
      "clash"
    )
    expect(profile.error).toBeNull()
    expect(profile.traffic).toBeUndefined()
    expect(profile.capability).toBeDefined()
  })

  it("keeps skip counts on the 400 that Conversion attaches them to", () => {
    const profile = previewProfile(
      "en",
      done({
        body: "No nodes were found!",
        httpStatus: 400,
        kind: { kind: "known-error", body: "No nodes were found!" },
        skipped: { parse: 0, capability: 1, name: 0 },
      }),
      "quanx"
    )
    expect(profile.error).toEqual({
      heading: "No nodes were found",
      wire: "No nodes were found!",
    })
    expect(profile.skipped).toBe("Skipped 1 node: 1 this client cannot import.")
    expect(profile.capability).toMatch(/Hysteria2/)
    expect(profile.traffic).toBeUndefined()
  })

  it("keeps an HTTP error heading without a known-error wire body", () => {
    const profile = previewProfile(
      "en",
      done({
        body: "upstream failed",
        httpStatus: 502,
        kind: { kind: "http" },
      }),
      "clash"
    )
    expect(profile.error).toEqual({
      heading: `${messages.en.status} 502`,
      wire: null,
    })
    expect(profile.skipped).toBeUndefined()
    expect(profile.capability).toBeUndefined()
  })

  it("omits capability on a known-error GET that never converted", () => {
    const profile = previewProfile(
      "zh",
      done({
        body: "Bad Gateway",
        httpStatus: 502,
        kind: { kind: "known-error", body: "Bad Gateway" },
      }),
      "clash"
    )
    expect(profile.error).toEqual({
      heading: "网关错误",
      wire: "Bad Gateway",
    })
    expect(profile.capability).toBeUndefined()
  })

  it("phrases skip and omitted counts on ok", () => {
    const profile = previewProfile(
      "en",
      done({
        body: "mode: rule\n",
        skipped: { parse: 1, capability: 0, name: 0 },
        omitted: { omittedUrlRegex: 3 },
      }),
      "clash"
    )
    expect(profile.error).toBeNull()
    expect(profile.skipped).toBe("Skipped 1 node: 1 could not be read.")
    expect(profile.omitted).toBe(
      "Omitted 3 URL-REGEX rules (this client cannot use them)."
    )
  })
})
