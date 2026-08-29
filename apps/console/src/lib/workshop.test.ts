import { describe, expect, it } from "vitest"

import { parseAccessToken } from "./service-contract.ts"
import {
  ACL4SSR_CLASSIC_FILES,
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  ACL4SSR_ONLINE_URL,
  acl4ssrConfigUrl,
  configPresetOf,
  configSelectionId,
} from "./acl4ssr-catalog.ts"
import { messages } from "./i18n.ts"
import { configChoiceGroups } from "./workshop-config.ts"
import {
  clashInstallUrl,
  evaluateWorkshop,
  parseServiceOrigin,
  type WorkshopFields,
} from "./workshop.ts"

function assembleSubscription(fields: WorkshopFields) {
  return evaluateWorkshop(fields).assembled
}

const VLESS =
  "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"
const VLESS_ENCODED =
  "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha"
const TWO_SOURCES_ENCODED =
  "vless%3A%2F%2Fu%40h%3A443%23A%7Css%3A%2F%2Fp%40h%3A8388%23B"
const ONLINE_ENCODED = encodeURIComponent(ACL4SSR_ONLINE_URL)

function input(overrides: Partial<WorkshopFields> = {}): WorkshopFields {
  return {
    serviceOrigin: "http://127.0.0.1:25500",
    accessToken: "",
    sources: [VLESS],
    target: "clash",
    configUrl: "",
    appendInfo: true,
    expand: true,
    ...overrides,
  }
}

describe("parseServiceOrigin", () => {
  it("canonicalizes http and https origins", () => {
    expect(parseServiceOrigin("http://127.0.0.1:25500/")).toBe(
      "http://127.0.0.1:25500"
    )
    expect(parseServiceOrigin("https://Example.COM:443")).toBe(
      "https://example.com"
    )
    expect(parseServiceOrigin("http://localhost:5173")).toBe(
      "http://localhost:5173"
    )
  })

  it("rejects userinfo, query, hash, and a non-empty path", () => {
    expect(parseServiceOrigin("http://user@host")).toBeNull()
    expect(parseServiceOrigin("https://a.example/path")).toBeNull()
    expect(parseServiceOrigin("https://a.example/?q=1")).toBeNull()
    expect(parseServiceOrigin("https://a.example/#x")).toBeNull()
    expect(parseServiceOrigin("ftp://a.example")).toBeNull()
  })
})

describe("parseAccessToken", () => {
  it("treats empty as anonymous and accepts the unreserved grammar", () => {
    expect(parseAccessToken("")).toEqual({ ok: true, token: "" })
    expect(parseAccessToken("deployer-token_1")).toEqual({
      ok: true,
      token: "deployer-token_1",
    })
    expect(parseAccessToken("A.z~9-")).toEqual({ ok: true, token: "A.z~9-" })
  })

  it("rejects slash, space, plus, and a 129th byte", () => {
    expect(parseAccessToken("has/slash").ok).toBe(false)
    expect(parseAccessToken("has space").ok).toBe(false)
    expect(parseAccessToken("has+plus").ok).toBe(false)
    expect(parseAccessToken("a".repeat(129)).ok).toBe(false)
  })
})

describe("assembleSubscription", () => {
  it("emits anonymous /sub with target then url, and omits append_info when on", () => {
    const assembled = assembleSubscription(input())
    expect(assembled.url).toBe(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}&expand=true`
    )
    expect(assembled.getTarget).toBe(
      `/sub?target=clash&url=${VLESS_ENCODED}&expand=true`
    )
    expect(assembled.overLimit).toBe(false)
    expect(assembled.url).not.toContain("append_info")
  })

  it("inserts a valid token as a raw path segment", () => {
    const assembled = assembleSubscription(
      input({ accessToken: "deployer-token_1" })
    )
    expect(assembled.url).toBe(
      `http://127.0.0.1:25500/sub/deployer-token_1?target=clash&url=${VLESS_ENCODED}&expand=true`
    )
    expect(assembled.getTarget).toBe(
      `/sub/deployer-token_1?target=clash&url=${VLESS_ENCODED}&expand=true`
    )
  })

  it("joins sources with | before encoding and keeps occurrence order", () => {
    const assembled = assembleSubscription(
      input({ sources: ["vless://u@h:443#A", "ss://p@h:8388#B"] })
    )
    expect(assembled.getTarget).toBe(
      `/sub?target=clash&url=${TWO_SOURCES_ENCODED}&expand=true`
    )
  })

  it("assembles more than five sources without a source-count cap", () => {
    const sources = [
      "vless://u@h:443#A",
      "ss://p@h:8388#B",
      "vless://u@h:443#C",
      "vless://u@h:443#D",
      "vless://u@h:443#E",
      "vless://u@h:443#F",
    ]
    const assembled = assembleSubscription(input({ sources }))
    expect(assembled.getTarget).toBe(
      `/sub?target=clash&url=${encodeURIComponent(sources.join("|"))}&expand=true`
    )
    expect(assembled.overLimit).toBe(false)
    expect(assembled.previewable).toBe(true)
  })

  it("appends config then append_info=false in that key order", () => {
    const assembled = assembleSubscription(
      input({
        target: "singbox",
        configUrl: ACL4SSR_ONLINE_URL,
        appendInfo: false,
      })
    )
    expect(assembled.getTarget).toBe(
      `/sub?target=singbox&url=${VLESS_ENCODED}&config=${ONLINE_ENCODED}&append_info=false&expand=true`
    )
  })

  it("writes expand=true by default and omits the key when the switch is off", () => {
    expect(assembleSubscription(input()).getTarget).toBe(
      `/sub?target=clash&url=${VLESS_ENCODED}&expand=true`
    )
    expect(assembleSubscription(input({ expand: false })).getTarget).toBe(
      `/sub?target=clash&url=${VLESS_ENCODED}`
    )
  })

  it("emits mihomo as the exact selected token", () => {
    const assembled = assembleSubscription(input({ target: "mihomo" }))
    expect(assembled.getTarget).toBe(
      `/sub?target=mihomo&url=${VLESS_ENCODED}&expand=true`
    )
  })

  it("lists a sibling URL for every released target without changing the primary", () => {
    const clash = assembleSubscription(input())
    expect(clash.siblings.map((sibling) => sibling.target)).toEqual([
      "clash",
      "mihomo",
      "quanx",
      "singbox",
      "loon",
      "egern",
    ])
    expect(clash.siblings.map((sibling) => sibling.getTarget)).toEqual([
      `/sub?target=clash&url=${VLESS_ENCODED}&expand=true`,
      `/sub?target=mihomo&url=${VLESS_ENCODED}&expand=true`,
      `/sub?target=quanx&url=${VLESS_ENCODED}&expand=true`,
      `/sub?target=singbox&url=${VLESS_ENCODED}&expand=true`,
      `/sub?target=loon&url=${VLESS_ENCODED}&expand=true`,
      `/sub?target=egern&url=${VLESS_ENCODED}&expand=true`,
    ])
    expect(clash.url).toBe(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}&expand=true`
    )
    expect(clash.url).toBe(clash.siblings[0]?.url)

    const loon = assembleSubscription(input({ target: "loon" }))
    expect(loon.getTarget).toBe(
      `/sub?target=loon&url=${VLESS_ENCODED}&expand=true`
    )
    expect(loon.url).toBe(loon.siblings[4]?.url)
    expect(loon.siblings).toHaveLength(6)

    const collapsed = assembleSubscription(input({ expand: false }))
    expect(
      collapsed.siblings.every(
        (sibling) => !sibling.getTarget.includes("expand=")
      )
    ).toBe(true)
  })

  it("flags GET targets longer than 8192 bytes and still returns the URL", () => {
    const atLimit = assembleSubscription(input({ sources: ["a".repeat(8158)] }))
    expect(atLimit.getTarget).toBe(
      `/sub?target=clash&url=${"a".repeat(8158)}&expand=true`
    )
    expect(new TextEncoder().encode(atLimit.getTarget ?? "").length).toBe(8192)
    expect(atLimit.overLimit).toBe(false)

    const over = assembleSubscription(input({ sources: ["a".repeat(8159)] }))
    expect(new TextEncoder().encode(over.getTarget ?? "").length).toBe(8193)
    expect(over.overLimit).toBe(true)
    expect(
      atLimit.siblings.find((sibling) => sibling.target === "clash")?.overLimit
    ).toBe(false)
    expect(
      atLimit.siblings.find((sibling) => sibling.target === "singbox")
        ?.overLimit
    ).toBe(true)
    expect(over.url).toBe(
      `http://127.0.0.1:25500/sub?target=clash&url=${"a".repeat(8159)}&expand=true`
    )
  })

  it("does not emit a URL when origin, token, sources, or config are incomplete", () => {
    expect(assembleSubscription(input({ serviceOrigin: "" })).url).toBeNull()
    expect(
      assembleSubscription(input({ accessToken: "has space" })).url
    ).toBeNull()
    expect(assembleSubscription(input({ sources: ["", ""] })).url).toBeNull()
    expect(
      assembleSubscription(input({ sources: ["vless://a|b"] })).url
    ).toBeNull()
    expect(
      assembleSubscription(
        input({ configUrl: "http://insecure.example/x.ini" })
      ).url
    ).toBeNull()
    expect(
      assembleSubscription(input({ sources: ["http://insecure.example/sub"] }))
        .url
    ).toBeNull()
    expect(assembleSubscription(input({ serviceOrigin: "" })).siblings).toEqual(
      []
    )
  })

  it("does not copy Conversion Service outbound host policy", () => {
    expect(
      assembleSubscription(input({ configUrl: "https://127.0.0.1/acl.ini" }))
        .url
    ).not.toBeNull()
  })
})

describe("configPresetOf", () => {
  it("maps empty, the 33 master files, and any other URL", () => {
    const files = [
      ...ACL4SSR_ONLINE_FILES,
      ...ACL4SSR_MINI_FILES,
      ...ACL4SSR_FULL_FILES,
      ...ACL4SSR_CLASSIC_FILES,
    ]
    expect(files).toHaveLength(33)
    expect(new Set(files).size).toBe(33)
    expect(configPresetOf("")).toEqual({ kind: "none" })
    expect(configPresetOf("  ")).toEqual({ kind: "none" })
    expect(acl4ssrConfigUrl("ACL4SSR_Online.ini")).toBe(
      "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini"
    )
    expect(acl4ssrConfigUrl("ACL4SSR.ini")).toBe(
      "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR.ini"
    )
    expect(acl4ssrConfigUrl("ACL4SSR_Online.ini")).not.toMatch(/[0-9a-f]{40}/)

    for (const file of ACL4SSR_ONLINE_FILES) {
      expect(configPresetOf(acl4ssrConfigUrl(file))).toEqual({
        kind: "online",
        file,
      })
    }
    for (const file of ACL4SSR_MINI_FILES) {
      expect(configPresetOf(acl4ssrConfigUrl(file))).toEqual({
        kind: "mini",
        file,
      })
    }
    for (const file of ACL4SSR_FULL_FILES) {
      expect(configPresetOf(acl4ssrConfigUrl(file))).toEqual({
        kind: "full",
        file,
      })
    }
    for (const file of ACL4SSR_CLASSIC_FILES) {
      expect(configPresetOf(acl4ssrConfigUrl(file))).toEqual({
        kind: "classic",
        file,
      })
    }
    expect(configPresetOf("https://example.com/custom.ini")).toEqual({
      kind: "custom",
    })
    const groups = configChoiceGroups(messages.en)
    expect(groups.map((group) => group.value)).toEqual([
      messages.en.configNone,
      messages.en.configOnline,
      messages.en.configMini,
      messages.en.configFull,
      messages.en.configClassic,
      messages.en.configCustom,
    ])
    expect(groups[4]?.items).toHaveLength(15)
  })
})

describe("clashInstallUrl", () => {
  it("wraps the Subscription URL, not a preview body", () => {
    const subscription =
      "http://127.0.0.1:25500/sub?target=clash&url=vless%3A%2F%2Fx"
    expect(clashInstallUrl(subscription)).toBe(
      `clash://install-config?url=${encodeURIComponent(subscription)}`
    )
  })
})

describe("evaluateWorkshop", () => {
  it("diagnoses fields with the same rules assemble uses", () => {
    const ready = evaluateWorkshop(input())
    expect(ready.assembled.previewable).toBe(true)
    expect(ready.assembled.clashInstall).toBe(true)
    expect(ready.canonicalOrigin).toBe("http://127.0.0.1:25500")
    expect(ready.originInvalid).toBe(false)
    expect(ready.sourceInvalid).toEqual([false])

    expect(
      evaluateWorkshop(input({ serviceOrigin: "" })).assembled.previewable
    ).toBe(false)
    expect(
      evaluateWorkshop(input({ sources: ["a".repeat(8171)] })).assembled
        .previewable
    ).toBe(false)
    expect(
      evaluateWorkshop(input({ target: "loon" })).assembled.clashInstall
    ).toBe(false)
    expect(
      evaluateWorkshop(input({ serviceOrigin: "not a url" })).originInvalid
    ).toBe(true)
    expect(
      evaluateWorkshop(input({ sources: ["http://insecure.example/sub"] }))
        .sourceInvalid
    ).toEqual([true])
    expect(configSelectionId({ kind: "none" }, false)).toBe("none")
    expect(configSelectionId({ kind: "custom" }, false)).toBe("custom")
    expect(configSelectionId({ kind: "none" }, true)).toBe("custom")
  })
})

describe("subscription URL golden", () => {
  it("round-trips shared cases through the Workshop adapter", async () => {
    const { readFile } = await import("node:fs/promises")
    const { resolve } = await import("node:path")
    const raw = await readFile(
      resolve(
        import.meta.dirname,
        "../../../../testdata/subscription-url/cases.json"
      ),
      "utf8"
    )
    const file = JSON.parse(raw) as {
      cases: Array<{
        id: string
        query: string
        path?: string
        workshop?: WorkshopFields
      }>
    }

    for (const testCase of file.cases) {
      if (testCase.workshop !== undefined) {
        const assembled = assembleSubscription(testCase.workshop)
        const path = testCase.path ?? "/sub"
        expect(assembled.getTarget, testCase.id).toBe(
          `${path}?${testCase.query}`
        )
        expect(assembled.url, testCase.id).toBe(
          `${testCase.workshop.serviceOrigin}${path}?${testCase.query}`
        )
      }
    }
  })
})
