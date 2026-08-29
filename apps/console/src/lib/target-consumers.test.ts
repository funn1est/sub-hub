import { describe, expect, it } from "vitest"

import { TARGETS, type Target } from "./service-contract.ts"
import { TARGET_CONSUMERS, targetConsumers } from "./target-consumers.ts"

describe("TARGET_CONSUMERS", () => {
  it("has a row for every released target in TARGETS order", () => {
    expect(Object.keys(TARGET_CONSUMERS)).toEqual([...TARGETS])
  })

  it("lists Stash on clash and mihomo as the same Mihomo consumers, not Shadowrocket", () => {
    const clash = targetConsumers("clash")
    const mihomo = targetConsumers("mihomo")
    expect(clash).toBe(mihomo)
    expect(clash).toEqual([
      "Clash Verge Rev",
      "FlClash",
      "Clash Meta for Android",
      "Stash",
      "OpenClash",
      "Karing",
      "Hiddify",
    ])
    expect(clash).not.toContain("Shadowrocket")
  })

  it("maps surge to Surge then Surfboard", () => {
    expect(targetConsumers("surge")).toEqual(["Surge", "Surfboard"])
  })

  it("names SFA and Throne on singbox, not v2rayN", () => {
    const singbox = targetConsumers("singbox")
    expect(singbox).toContain("SFA")
    expect(singbox).toContain("Throne")
    expect(singbox).not.toContain("v2rayN")
  })

  it("gives every target at least one consumer", () => {
    for (const target of TARGETS) {
      expect(targetConsumers(target as Target).length).toBeGreaterThanOrEqual(1)
    }
  })
})
