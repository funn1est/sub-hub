import { describe, expect, it } from "vitest"

import {
  composePersisted,
  createConsolePersist,
  defaultLocale,
  PERSIST_KEY,
  serializePersisted,
  workshopFieldsOf,
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
  expand: false,
}

function memoryStorage(initial: Iterable<readonly [string, string]> = []) {
  const data = new Map<string, string>(initial)
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => {
      data.set(key, value)
    },
    removeItem: (key: string) => {
      data.delete(key)
    },
  }
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

    const storage = memoryStorage([[PERSIST_KEY, raw]])
    const loaded = createConsolePersist(storage).getState()
    expect(loaded.accessToken).toBe("deployer-token_1")
    expect(loaded).toEqual(sample)
    expect(loaded).not.toHaveProperty("previewBody")
  })

  it("round-trips more than five sources without truncating", () => {
    const six = {
      ...sample,
      sources: [
        "vless://u@h:443#A",
        "ss://p@h:8388#B",
        "vless://u@h:443#C",
        "vless://u@h:443#D",
        "vless://u@h:443#E",
        "vless://u@h:443#F",
      ],
    }
    const loaded = createConsolePersist(
      memoryStorage([[PERSIST_KEY, serializePersisted(six)]])
    ).getState()
    expect(loaded.sources).toEqual(six.sources)
  })

  it("falls back to defaults when the stored blob is missing or invalid", () => {
    const empty = createConsolePersist(memoryStorage(), {
      locale: "en",
      serviceOrigin: "http://127.0.0.1:25500",
    }).getState()
    expect(empty).toEqual({
      locale: "en",
      theme: "system",
      serviceOrigin: "http://127.0.0.1:25500",
      accessToken: "",
      sources: [""],
      target: "clash",
      configUrl: "",
      appendInfo: true,
      expand: true,
    })

    const junk = createConsolePersist(
      memoryStorage([[PERSIST_KEY, "not-json"]])
    ).getState()
    expect(junk.target).toBe("clash")
    expect(junk.sources).toEqual([""])
    expect(junk.accessToken).toBe("")
    expect(junk.expand).toBe(true)
  })

  it("treats a missing expand field as the default on", () => {
    const { expand, ...withoutExpand } = sample
    expect(expand).toBe(false)
    const loaded = createConsolePersist(
      memoryStorage([[PERSIST_KEY, JSON.stringify(withoutExpand)]])
    ).getState()
    expect(loaded.expand).toBe(true)
  })

  it("writes a flat PersistedWorkshop blob, not Zustand's {state, version} wrapper", () => {
    const storage = memoryStorage()
    const store = createConsolePersist(storage)
    store.setState(sample)
    const raw = storage.data.get(PERSIST_KEY)
    expect(raw).toBeDefined()
    const parsed = JSON.parse(raw ?? "null") as unknown
    expect(parsed).toEqual(sample)
    expect(parsed).not.toHaveProperty("state")
    expect(parsed).not.toHaveProperty("version")
  })

  it("strips a preview body when setState includes one", () => {
    const storage = memoryStorage()
    const store = createConsolePersist(storage)
    store.setState({
      ...sample,
      previewBody: "vless://uuid:password@secret.example:443",
    } as PersistedWorkshop & { previewBody: string })
    const raw = storage.data.get(PERSIST_KEY) ?? ""
    expect(raw).not.toContain("previewBody")
    expect(raw).not.toContain("uuid:password")
    expect(raw).not.toContain("secret.example")
    expect(JSON.parse(raw)).toEqual(sample)
  })

  it("splits conversion fields from Console chrome and composes them back", () => {
    expect(workshopFieldsOf(sample)).toEqual({
      serviceOrigin: sample.serviceOrigin,
      accessToken: sample.accessToken,
      sources: sample.sources,
      target: sample.target,
      configUrl: sample.configUrl,
      appendInfo: sample.appendInfo,
      expand: sample.expand,
    })
    expect(
      composePersisted(workshopFieldsOf(sample), {
        locale: "en",
        theme: "dark",
      })
    ).toEqual({ ...sample, locale: "en", theme: "dark" })
  })

  it("round-trips a Classic ACL4SSR config URL", () => {
    const classic =
      "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR.ini"
    const storage = memoryStorage()
    const store = createConsolePersist(storage)
    store.setState({ ...sample, configUrl: classic })
    expect(JSON.parse(storage.data.get(PERSIST_KEY) ?? "").configUrl).toBe(
      classic
    )
    expect(
      workshopFieldsOf(createConsolePersist(storage).getState()).configUrl
    ).toBe(classic)
  })
})
