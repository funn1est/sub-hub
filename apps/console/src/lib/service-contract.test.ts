import { describe, expect, it } from "vitest"

import {
  EXPOSED_HEADERS,
  GET_TARGET_LIMIT_BYTES,
  KNOWN_SERVICE_ERRORS,
  MAX_SOURCES,
  QUERY_KEYS,
  SKIPPED_HEADER,
  TARGETS,
  VERSION_PATH,
  fallbackDownloadName,
  isQueryKey,
  isTarget,
  decodeSubGetTarget,
  encodeSubGetTarget,
  parseSkippedFromHeaders,
  parseSkippedHeader,
} from "./service-contract.ts"

describe("Conversion Service GET contract", () => {
  it("lists the closed target tokens including the clash alias", () => {
    expect(TARGETS).toEqual([
      "clash",
      "mihomo",
      "quanx",
      "singbox",
      "loon",
      "egern",
    ])
    expect(isTarget("clash")).toBe(true)
    expect(isTarget("clashmeta")).toBe(false)
  })

  it("pins the HTTP query keys, source cap, and GET target byte limit", () => {
    expect(QUERY_KEYS).toEqual([
      "target",
      "url",
      "config",
      "append_info",
      "insert",
    ])
    expect(isQueryKey("insert")).toBe(true)
    expect(MAX_SOURCES).toBe(5)
    expect(GET_TARGET_LIMIT_BYTES).toBe(8192)
  })

  it("pins the exact English error bodies", () => {
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
  })

  it("treats clash as the Mihomo wire alias and keeps append_info off the interval header", () => {
    expect(fallbackDownloadName("clash")).toBe(fallbackDownloadName("mihomo"))
    expect(QUERY_KEYS).toContain("append_info")
    expect(EXPOSED_HEADERS).toContain("subscription-userinfo")
    expect(EXPOSED_HEADERS).toContain("profile-update-interval")
  })

  it("pins CORS-exposed headers and skip grammar", () => {
    expect(EXPOSED_HEADERS).toEqual([
      "content-disposition",
      "profile-update-interval",
      "subscription-userinfo",
      "x-subconverter-result",
      "x-subconverter-omitted-rules",
      SKIPPED_HEADER,
    ])
    expect(VERSION_PATH).toBe("/version")
    expect(parseSkippedHeader("parse=1;capability=4;name=0")).toEqual({
      parse: 1,
      capability: 4,
      name: 0,
    })
    expect(
      parseSkippedFromHeaders([
        { name: SKIPPED_HEADER, value: "parse=1;capability=4;name=0" },
      ])
    ).toEqual({ parse: 1, capability: 4, name: 0 })
  })

  it("treats insert as a known query key that is never reassembled", () => {
    expect(isQueryKey("insert")).toBe(true)
    expect(isQueryKey("filename")).toBe(false)
  })

  it("names download fallbacks per wire target", () => {
    expect(fallbackDownloadName("mihomo")).toBe("sub-hub-mihomo.yaml")
    expect(fallbackDownloadName("clash")).toBe("sub-hub-mihomo.yaml")
  })

  it("encodes request-target without insert and decodes plus as literal", () => {
    const getTarget = encodeSubGetTarget({
      accessToken: "",
      target: "clash",
      sources: ["ss://aes-128-gcm:p+ss@example.com:8388#Plus"],
      configUrl: "",
      appendInfo: true,
    })
    expect(getTarget).toBe(
      "/sub?target=clash&url=ss%3A%2F%2Faes-128-gcm%3Ap%2Bss%40example.com%3A8388%23Plus"
    )
    expect(getTarget).not.toContain("insert")
    const decoded = decodeSubGetTarget(`http://127.0.0.1:25500${getTarget}`)
    expect(decoded.ok).toBe(true)
    if (decoded.ok) {
      expect(decoded.sources).toEqual([
        "ss://aes-128-gcm:p+ss@example.com:8388#Plus",
      ])
    }
    expect(
      decodeSubGetTarget(
        "http://127.0.0.1:25500/sub/?target=clash&url=vless://x"
      ).ok
    ).toBe(false)
  })
})
