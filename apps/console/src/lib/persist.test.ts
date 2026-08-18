import { describe, expect, it } from "vitest"

import {
  defaultLocale,
  loadPersisted,
  PERSIST_KEY,
  serializePersisted,
  type PersistedWorkshop,
} from "./persist.ts"

const sample: PersistedWorkshop = {
  locale: "zh",
  theme: "system",
  serviceOrigin: "http://127.0.0.1:25500",
  accessToken: "deployer-token_1",
  sources: ["vless://u@h:443#A"],
  target: "clash",
  configUrl: "",
  appendInfo: true,
}

describe("defaultLocale", () => {
  it("selects zh only when navigator.language starts with zh", () => {
    expect(defaultLocale("zh-CN")).toBe("zh")
    expect(defaultLocale("zh")).toBe("zh")
    expect(defaultLocale("en-US")).toBe("en")
    expect(defaultLocale("ja")).toBe("en")
  })
})

describe("persist", () => {
  it("round-trips the access token and never serializes a preview body", () => {
    const extra = {
      ...sample,
      previewBody: "vless://uuid:password@secret.example:443",
    } as PersistedWorkshop & { previewBody: string }

    const raw = serializePersisted(extra)
    expect(raw).not.toContain("previewBody")
    expect(raw).not.toContain("uuid:password")
    expect(raw).not.toContain("secret.example")
    expect(JSON.parse(raw)).toEqual(sample)

    const storage = new Map<string, string>([[PERSIST_KEY, raw]])
    const loaded = loadPersisted({
      getItem: (key) => storage.get(key) ?? null,
    })
    expect(loaded.accessToken).toBe("deployer-token_1")
    expect(loaded).toEqual(sample)
    expect(loaded).not.toHaveProperty("previewBody")
  })

  it("falls back to defaults when the stored blob is missing or invalid", () => {
    const empty = loadPersisted(
      { getItem: () => null },
      { locale: "en", serviceOrigin: "http://127.0.0.1:25500" },
    )
    expect(empty).toEqual({
      locale: "en",
      theme: "system",
      serviceOrigin: "http://127.0.0.1:25500",
      accessToken: "",
      sources: [""],
      target: "clash",
      configUrl: "",
      appendInfo: true,
    })

    const junk = loadPersisted({ getItem: () => "not-json" })
    expect(junk.target).toBe("clash")
    expect(junk.sources).toEqual([""])
    expect(junk.accessToken).toBe("")
  })
})
