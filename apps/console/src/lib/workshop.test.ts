import { describe, expect, it } from "vitest"

import {
  assembleSubscription,
  parseAccessToken,
  parseServiceOrigin,
  parseSubscriptionUrl,
  type SubscriptionAssemblyInput,
} from "./service-contract.ts"
import {
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  ACL4SSR_ONLINE_URL,
  acl4ssrConfigUrl,
  clashInstallUrl,
  configPresetOf,
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

  it("still returns the URL when the GET target is 8192 bytes or more", () => {
    const atLimit = assembleSubscription(input({ sources: ["a".repeat(8170)] }))
    expect(atLimit.getTarget).toBe(`/sub?target=clash&url=${"a".repeat(8170)}`)
    expect(new TextEncoder().encode(atLimit.getTarget ?? "").length).toBe(8192)
    expect(atLimit.overLimit).toBe(true)
    expect(atLimit.url).toBe(
      `http://127.0.0.1:25500/sub?target=clash&url=${"a".repeat(8170)}`
    )

    const under = assembleSubscription(input({ sources: ["a".repeat(8169)] }))
    expect(new TextEncoder().encode(under.getTarget ?? "").length).toBe(8191)
    expect(under.overLimit).toBe(false)
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
