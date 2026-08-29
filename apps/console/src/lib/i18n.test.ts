import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

import { KNOWN_SERVICE_ERRORS, TARGETS } from "./service-contract.ts"
import {
  knownErrorTitle,
  messages,
  omittedSummary,
  skippedSummary,
  targetHint,
} from "./i18n.ts"

describe("known Conversion Service errors", () => {
  it("has a distinct zh and en title for every exact English body", async () => {
    const raw = await readFile(
      resolve(
        import.meta.dirname,
        "../../../../testdata/subscription-url/cases.json"
      ),
      "utf8"
    )
    const errors = (JSON.parse(raw) as { contract: { errors: string[] } })
      .contract.errors
    expect(KNOWN_SERVICE_ERRORS).toEqual(errors)

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

describe("remote config copy", () => {
  it("names the field as remote config, not an ACL4SSR-only control", () => {
    expect(messages.en.config).toBe("Remote config")
    expect(messages.zh.config).toBe("远端配置")
    expect(messages.en.config).not.toMatch(/ACL4SSR/i)
    expect(messages.zh.config).not.toMatch(/ACL4SSR/i)
    expect(messages.en.configHint).toContain("config=")
    expect(messages.zh.configHint).toContain("config=")
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

describe("omittedSummary", () => {
  it("names the omitted URL-REGEX count in zh and en", () => {
    expect(omittedSummary("en", 3)).toBe(
      "Omitted 3 URL-REGEX rules (unsupported on this target)."
    )
    expect(omittedSummary("zh", 3)).toBe(
      "省略 3 条 URL-REGEX 规则（此 target 不支持）。"
    )
  })
})

describe("targetHint", () => {
  it("names Stash on clash in en and zh, never Shadowrocket", () => {
    const en = targetHint("en", "clash")
    const zh = targetHint("zh", "clash")
    expect(en).toBe(
      "Imported by: Clash Verge Rev, FlClash, Clash Meta for Android, Stash, OpenClash, Karing, Hiddify. Mihomo YAML (clash is the compatibility name)."
    )
    expect(zh).toBe(
      "以下客户端导入此文档：Clash Verge Rev, FlClash, Clash Meta for Android, Stash, OpenClash, Karing, Hiddify。Mihomo YAML（clash 是兼容名）。"
    )
    expect(en).not.toMatch(/Shadowrocket/i)
    expect(zh).not.toMatch(/Shadowrocket/i)
    expect(targetHint("en", "mihomo")).toBe(en)
  })

  it("names Surfboard on surge in en and zh", () => {
    expect(targetHint("en", "surge")).toBe(
      "Imported by: Surge, Surfboard. Surfboard follows Surge and does not support VLESS."
    )
    expect(targetHint("zh", "surge")).toBe(
      "以下客户端导入此文档：Surge, Surfboard。Surfboard 跟随 Surge 语法，不支持 VLESS。"
    )
  })

  it("never names Shadowrocket on any released target", () => {
    for (const target of TARGETS) {
      expect(targetHint("en", target)).not.toMatch(/Shadowrocket/i)
      expect(targetHint("zh", target)).not.toMatch(/Shadowrocket/i)
    }
  })
})
