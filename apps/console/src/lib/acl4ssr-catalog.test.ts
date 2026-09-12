import { describe, expect, it } from "vitest"

import {
  ACL4SSR_FAMILIES,
  ACL4SSR_PRESETS,
  acl4ssrListed,
} from "./acl4ssr-catalog.ts"
import { messages } from "./i18n.ts"

describe("ACL4SSR_PRESETS", () => {
  it("groups INIs by family in combobox order", () => {
    expect(Object.keys(ACL4SSR_PRESETS)).toEqual([
      "online",
      "mini",
      "full",
      "classic",
    ])
    expect(ACL4SSR_FAMILIES).toEqual(["online", "mini", "full", "classic"])
    expect(Object.keys(messages.en.configFamilies)).toEqual(ACL4SSR_FAMILIES)
    expect(Object.keys(messages.zh.configFamilies)).toEqual(ACL4SSR_FAMILIES)
  })

  it("lists every INI once, with Online.ini as ads and China split", () => {
    const listed = acl4ssrListed()
    const files = listed.map((preset) => preset.file)
    expect(files).toHaveLength(33)
    expect(new Set(files).size).toBe(33)
    expect(
      ACL4SSR_PRESETS.online.find(
        (preset) => preset.file === "ACL4SSR_Online.ini"
      )
    ).toMatchObject({ effect: "adsChinaSplit" })
    expect(
      listed.find((preset) => preset.file === "ACL4SSR_Online_NoAuto.ini")
    ).toMatchObject({ effect: "noAuto" })
    expect(
      listed.find(
        (preset) => preset.file === "ACL4SSR_Online_Full_Netflix.ini"
      )
    ).toMatchObject({ effect: "netflix" })
    expect(
      listed.find(
        (preset) => preset.file === "ACL4SSR_NoAuto_NoApple_NoMicrosoft.ini"
      )
    ).toMatchObject({ effect: "noAutoNoAppleNoMicrosoft" })
    for (const preset of listed) {
      expect(messages.en.configEffects[preset.effect].length).toBeGreaterThan(0)
      expect(messages.zh.configEffects[preset.effect].length).toBeGreaterThan(0)
    }
  })
})
