import { describe, expect, it } from "vitest"

import { parseAccessToken } from "./service-contract.ts"
import {
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  ACL4SSR_ONLINE_URL,
  acl4ssrConfigUrl,
  configPresetOf,
  configSelectionId,
} from "./acl4ssr-catalog.ts"
import {
  applyPaste,
  assembleSubscription,
  clashInstallUrl,
  evaluateWorkshop,
  parseServiceOrigin,
  parseSubscriptionUrl,
  subscriptionPasteFrom,
  type SubscriptionAssemblyInput,
} from "./workshop.ts"

const VLESS =
  "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"
const VLESS_ENCODED =
  "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha"
const TWO_SOURCES_ENCODED =
  "vless%3A%2F%2Fu%40h%3A443%23A%7Css%3A%2F%2Fp%40h%3A8388%23B"
const ONLINE_ENCODED = encodeURIComponent(ACL4SSR_ONLINE_URL)

function input(
  overrides: Partial<SubscriptionAssemblyInput> = {}
): SubscriptionAssemblyInput {
  return {
    serviceOrigin: "http://127.0.0.1:25500",
    accessToken: "",
    sources: [VLESS],
    target: "clash",
    configUrl: "",
    appendInfo: true,
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
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}`
    )
    expect(assembled.getTarget).toBe(`/sub?target=clash&url=${VLESS_ENCODED}`)
    expect(assembled.overLimit).toBe(false)
    expect(assembled.url).not.toContain("append_info")
  })

  it("inserts a valid token as a raw path segment", () => {
    const assembled = assembleSubscription(
      input({ accessToken: "deployer-token_1" })
    )
    expect(assembled.url).toBe(
      `http://127.0.0.1:25500/sub/deployer-token_1?target=clash&url=${VLESS_ENCODED}`
    )
    expect(assembled.getTarget).toBe(
      `/sub/deployer-token_1?target=clash&url=${VLESS_ENCODED}`
    )
  })

  it("joins sources with | before encoding and keeps occurrence order", () => {
    const assembled = assembleSubscription(
      input({ sources: ["vless://u@h:443#A", "ss://p@h:8388#B"] })
    )
    expect(assembled.getTarget).toBe(
      `/sub?target=clash&url=${TWO_SOURCES_ENCODED}`
    )
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
      `/sub?target=singbox&url=${VLESS_ENCODED}&config=${ONLINE_ENCODED}&append_info=false`
    )
  })

  it("emits mihomo as the exact selected token", () => {
    const assembled = assembleSubscription(input({ target: "mihomo" }))
    expect(assembled.getTarget).toBe(`/sub?target=mihomo&url=${VLESS_ENCODED}`)
  })

  it("flags GET targets longer than 8192 bytes and still returns the URL", () => {
    const atLimit = assembleSubscription(input({ sources: ["a".repeat(8170)] }))
    expect(atLimit.getTarget).toBe(`/sub?target=clash&url=${"a".repeat(8170)}`)
    expect(new TextEncoder().encode(atLimit.getTarget ?? "").length).toBe(8192)
    expect(atLimit.overLimit).toBe(false)

    const over = assembleSubscription(input({ sources: ["a".repeat(8171)] }))
    expect(new TextEncoder().encode(over.getTarget ?? "").length).toBe(8193)
    expect(over.overLimit).toBe(true)
    expect(over.url).toBe(
      `http://127.0.0.1:25500/sub?target=clash&url=${"a".repeat(8171)}`
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
  })

  it("does not copy Conversion Service outbound host policy", () => {
    expect(
      assembleSubscription(input({ configUrl: "https://127.0.0.1/acl.ini" }))
        .url
    ).not.toBeNull()
  })
})

describe("parseSubscriptionUrl", () => {
  it("round-trips /sub and /sub/:token plus the known query keys", () => {
    const anonymous = parseSubscriptionUrl(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}`
    )
    expect(anonymous.ok).toBe(true)
    if (!anonymous.ok) {
      return
    }
    expect(anonymous.workshop).toEqual({
      serviceOrigin: "http://127.0.0.1:25500",
      accessToken: "",
      sources: [VLESS],
      target: "clash",
      configUrl: "",
      appendInfo: true,
    })
    expect(anonymous.warnings).toEqual([])

    const tokenized = parseSubscriptionUrl(
      `https://sub-hub.example/sub/deployer-token_1?target=loon&url=${TWO_SOURCES_ENCODED}&config=${ONLINE_ENCODED}&append_info=false`
    )
    expect(tokenized.ok).toBe(true)
    if (!tokenized.ok) {
      return
    }
    expect(tokenized.workshop.serviceOrigin).toBe("https://sub-hub.example")
    expect(tokenized.workshop.accessToken).toBe("deployer-token_1")
    expect(tokenized.workshop.sources).toEqual([
      "vless://u@h:443#A",
      "ss://p@h:8388#B",
    ])
    expect(tokenized.workshop.target).toBe("loon")
    expect(tokenized.workshop.configUrl).toBe(ACL4SSR_ONLINE_URL)
    expect(tokenized.workshop.appendInfo).toBe(false)
  })

  it("fills known keys, warns on unknown keys, and does not copy them onto a new URL", () => {
    const parsed = parseSubscriptionUrl(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}&filename=x&insert=false`
    )
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) {
      return
    }
    expect(parsed.warnings).toContain("unknown-keys")
    expect(parsed.warnings).not.toContain("duplicate-keys")
    const again = assembleSubscription({
      serviceOrigin: parsed.workshop.serviceOrigin ?? "",
      accessToken: parsed.workshop.accessToken ?? "",
      sources: parsed.workshop.sources ?? [""],
      target: parsed.workshop.target ?? "clash",
      configUrl: parsed.workshop.configUrl ?? "",
      appendInfo: parsed.workshop.appendInfo ?? true,
    })
    expect(again.url).toBe(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}`
    )
    expect(again.url).not.toContain("filename")
    expect(again.url).not.toContain("insert")
  })

  it("keeps a literal plus in query values instead of treating it as space", () => {
    const parsed = parseSubscriptionUrl(
      "http://127.0.0.1:25500/sub?target=clash&url=ss%3A%2F%2Faes-128-gcm%3Ap%2Bss%40example.com%3A8388%23Plus"
    )
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) {
      return
    }
    expect(parsed.workshop.sources).toEqual([
      "ss://aes-128-gcm:p+ss@example.com:8388#Plus",
    ])
  })

  it("rejects a trailing slash on /sub/", () => {
    expect(
      parseSubscriptionUrl(
        `http://127.0.0.1:25500/sub/?target=clash&url=${VLESS_ENCODED}`
      ).ok
    ).toBe(false)
  })

  it("warns on insert, empty url slots, and http sources without copying them", () => {
    const insert = parseSubscriptionUrl(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}&insert=true`
    )
    expect(insert.ok).toBe(true)
    if (insert.ok) {
      expect(insert.warnings).toContain("invalid-insert")
    }

    const emptySlots = parseSubscriptionUrl(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}%7C%7C${VLESS_ENCODED}`
    )
    expect(emptySlots.ok).toBe(true)
    if (emptySlots.ok) {
      expect(emptySlots.warnings).toContain("empty-sources")
      expect(emptySlots.workshop.sources).toEqual([VLESS, VLESS])
    }

    const httpSource = parseSubscriptionUrl(
      "http://127.0.0.1:25500/sub?target=clash&url=http%3A%2F%2Finsecure.example%2Fsub"
    )
    expect(httpSource.ok).toBe(true)
    if (httpSource.ok) {
      expect(httpSource.warnings).toContain("http-sources")
      expect(httpSource.workshop.sources).toEqual([
        "http://insecure.example/sub",
      ])
    }
  })

  it("warns on an unknown target and does not write window.location", () => {
    const parsed = parseSubscriptionUrl(
      `http://127.0.0.1:25500/sub?target=surge&url=${VLESS_ENCODED}`
    )
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) {
      return
    }
    expect(parsed.warnings).toContain("invalid-target")
    expect(parsed.workshop.target).toBeUndefined()
  })
})

describe("configPresetOf", () => {
  it("maps empty, the 18 master files, and any other URL", () => {
    const files = [
      ...ACL4SSR_ONLINE_FILES,
      ...ACL4SSR_MINI_FILES,
      ...ACL4SSR_FULL_FILES,
    ]
    expect(files).toHaveLength(18)
    expect(new Set(files).size).toBe(18)
    expect(configPresetOf("")).toEqual({ kind: "none" })
    expect(configPresetOf("  ")).toEqual({ kind: "none" })
    expect(acl4ssrConfigUrl("ACL4SSR_Online.ini")).toBe(
      "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini"
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
    expect(configPresetOf("https://example.com/custom.ini")).toEqual({
      kind: "custom",
    })
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

describe("subscriptionPasteFrom", () => {
  it("imports a Conversion Service Subscription URL and ignores provider /sub sources", () => {
    const assembled = subscriptionPasteFrom(
      `http://127.0.0.1:25500/sub?target=clash&url=${VLESS_ENCODED}`
    )
    expect(assembled).not.toBeNull()
    expect(assembled?.workshop.sources).toEqual([VLESS])
    expect(assembled?.workshop.target).toBe("clash")

    const tokenized = subscriptionPasteFrom(
      `https://sub-hub.example/sub/deployer-token_1?target=loon&url=${VLESS_ENCODED}`
    )
    expect(tokenized?.workshop.accessToken).toBe("deployer-token_1")
    expect(
      subscriptionPasteFrom("https://sub-hub.example/sub/deployer-token_1")
        ?.workshop.accessToken
    ).toBe("deployer-token_1")

    expect(subscriptionPasteFrom(VLESS)).toBeNull()
    expect(
      subscriptionPasteFrom("https://provider.example/sub?token=abc")
    ).toBeNull()
    expect(subscriptionPasteFrom("http://127.0.0.1:25500/sub")).toBeNull()
    expect(subscriptionPasteFrom("https://example.com/subscribe")).toBeNull()
  })
})

describe("applyPaste and evaluateWorkshop", () => {
  it("merges a successful paste onto the Workshop conversion fields", () => {
    const next = applyPaste(input(), {
      ok: true,
      workshop: {
        serviceOrigin: "http://127.0.0.1:25500",
        accessToken: "deployer-token_1",
        sources: [VLESS],
        target: "loon",
        configUrl: ACL4SSR_ONLINE_URL,
        appendInfo: false,
      },
      warnings: [],
    })
    expect(next.accessToken).toBe("deployer-token_1")
    expect(next.target).toBe("loon")
    expect(next.appendInfo).toBe(false)
    expect(Object.keys(next).sort()).toEqual([
      "accessToken",
      "appendInfo",
      "configUrl",
      "serviceOrigin",
      "sources",
      "target",
    ])
  })

  it("diagnoses fields with the same rules assemble uses", () => {
    const ready = evaluateWorkshop(input())
    expect(ready.assembled.previewable).toBe(true)
    expect(ready.assembled.clashInstall).toBe(true)
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
        workshop?: SubscriptionAssemblyInput
        workshopParse?: { ok: true; warnings: string[] }
        assembleOmits?: string[]
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
        const parsed = parseSubscriptionUrl(assembled.url ?? "")
        expect(parsed.ok, testCase.id).toBe(true)
        if (parsed.ok) {
          expect(parsed.workshop, testCase.id).toEqual({
            serviceOrigin: testCase.workshop.serviceOrigin,
            accessToken: testCase.workshop.accessToken,
            sources: testCase.workshop.sources,
            target: testCase.workshop.target,
            configUrl: testCase.workshop.configUrl,
            appendInfo: testCase.workshop.appendInfo,
          })
        }
      }

      if (testCase.workshopParse !== undefined) {
        const parsed = parseSubscriptionUrl(
          `http://127.0.0.1:25500/sub?${testCase.query}`
        )
        expect(parsed.ok, testCase.id).toBe(testCase.workshopParse.ok)
        if (parsed.ok) {
          expect(parsed.warnings, testCase.id).toEqual(
            testCase.workshopParse.warnings
          )
        }
      }

      if (testCase.assembleOmits !== undefined) {
        const parsed = parseSubscriptionUrl(
          `http://127.0.0.1:25500/sub?${testCase.query}`
        )
        expect(parsed.ok, testCase.id).toBe(true)
        if (!parsed.ok) {
          continue
        }
        const again = assembleSubscription({
          serviceOrigin: parsed.workshop.serviceOrigin ?? "",
          accessToken: parsed.workshop.accessToken ?? "",
          sources: parsed.workshop.sources ?? [""],
          target: parsed.workshop.target ?? "clash",
          configUrl: parsed.workshop.configUrl ?? "",
          appendInfo: parsed.workshop.appendInfo ?? true,
        })
        for (const omitted of testCase.assembleOmits) {
          expect(again.url, testCase.id).not.toContain(omitted)
        }
      }
    }
  })
})
