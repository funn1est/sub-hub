import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

import { KNOWN_SERVICE_ERRORS } from "./service-contract.ts"
import { CLIENT_TARGETS } from "./workshop.ts"
import {
  SOURCE_REPO,
  capabilityHint,
  clientTargetLabel,
  knownErrorTitle,
  messages,
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
    expect(messages.en.configNone).toContain("PROXY/AUTO")
    expect(messages.zh.configNone).toContain("PROXY/AUTO")
    expect(messages.en.configHint).toMatch(/ads or China split/i)
    expect(messages.zh.configHint).toMatch(/广告和分流/)
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
  })

  it("names Surfboard on surge in en and zh", () => {
    expect(targetHint("en", "surge")).toBe("Imported by: Surge, Surfboard.")
    expect(targetHint("zh", "surge")).toBe(
      "以下客户端导入此文档：Surge, Surfboard。"
    )
  })

  it("never names Shadowrocket on any Workshop client", () => {
    for (const target of CLIENT_TARGETS) {
      expect(targetHint("en", target)).not.toMatch(/Shadowrocket/i)
      expect(targetHint("zh", target)).not.toMatch(/Shadowrocket/i)
      expect(capabilityHint("en", target)).not.toMatch(/Shadowrocket/i)
      expect(capabilityHint("zh", target)).not.toMatch(/Shadowrocket/i)
      expect(clientTargetLabel("en", target)).not.toMatch(/Shadowrocket/i)
    }
  })
})

describe("client-first copy", () => {
  it("names the phone app, not the wire token", () => {
    expect(clientTargetLabel("en", "clash")).toBe("Clash / Mihomo")
    expect(clientTargetLabel("zh", "quanx")).toBe("Quantumult X")
    expect(clientTargetLabel("en", "singbox")).toBe("sing-box")
    expect(Object.keys(messages.en.client)).toEqual([...CLIENT_TARGETS])
    expect(messages.en.client.clash.wireNote).toMatch(/Mihomo YAML/)
    expect(messages.zh.client.clash.wireNote).toMatch(/Mihomo YAML/)
    for (const target of CLIENT_TARGETS) {
      if (target === "clash") {
        continue
      }
      expect("wireNote" in messages.en.client[target]).toBe(false)
      expect("wireNote" in messages.zh.client[target]).toBe(false)
    }
  })

  it("states Surge drops every VLESS node", () => {
    expect(capabilityHint("en", "surge")).toMatch(/skip every VLESS/i)
    expect(capabilityHint("zh", "surge")).toMatch(/VLESS/)
  })
})

describe("locale key alignment", () => {
  it("keeps the same message keys in zh and en", () => {
    expect(Object.keys(messages.zh)).toEqual(Object.keys(messages.en))
    expect(Object.keys(messages.zh.configEffects)).toEqual(
      Object.keys(messages.en.configEffects)
    )
    expect(Object.keys(messages.zh.configFamilies)).toEqual(
      Object.keys(messages.en.configFamilies)
    )
    expect(Object.keys(messages.zh.client)).toEqual(
      Object.keys(messages.en.client)
    )
    expect(Object.keys(messages.zh.client.clash)).toEqual(
      Object.keys(messages.en.client.clash)
    )
  })
})

describe("AGPL source offer", () => {
  it("names AGPL and the GitHub source URL in both locales", async () => {
    expect(SOURCE_REPO).toBe("https://github.com/funn1est/sub-hub")
    expect(messages.en.agpl).toMatch(/AGPL/)
    expect(messages.zh.agpl).toMatch(/AGPL/)
    expect(messages.en.agpl).toContain("github.com/funn1est/sub-hub")
    expect(messages.zh.agpl).toContain("github.com/funn1est/sub-hub")
    const workshop = await readFile(
      resolve(import.meta.dirname, "../components/workshop.tsx"),
      "utf8"
    )
    expect(workshop).toMatch(/href=\{SOURCE_REPO\}/)
  })
})
