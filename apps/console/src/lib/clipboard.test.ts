import { describe, expect, it } from "vitest"

import { writeTextWithFallback } from "./clipboard.ts"

describe("writeTextWithFallback", () => {
  it("uses Clipboard API when writeText succeeds", async () => {
    const wrote: string[] = []
    const exec: string[] = []
    await writeTextWithFallback("https://example/sub", {
      writeText: async (text) => {
        wrote.push(text)
      },
      execCommandCopy: (text) => {
        exec.push(text)
        return true
      },
    })
    expect(wrote).toEqual(["https://example/sub"])
    expect(exec).toEqual([])
  })

  it("falls back to execCommand when writeText rejects", async () => {
    const exec: string[] = []
    await writeTextWithFallback("https://example/sub", {
      writeText: () => Promise.reject(new Error("denied")),
      execCommandCopy: (text) => {
        exec.push(text)
        return true
      },
    })
    expect(exec).toEqual(["https://example/sub"])
  })

  it("uses execCommand when Clipboard API is absent", async () => {
    const exec: string[] = []
    await writeTextWithFallback("https://example/sub", {
      execCommandCopy: (text) => {
        exec.push(text)
        return true
      },
    })
    expect(exec).toEqual(["https://example/sub"])
  })

  it("rejects when both Clipboard API and execCommand fail", async () => {
    await expect(
      writeTextWithFallback("https://example/sub", {
        writeText: () => Promise.reject(new Error("denied")),
        execCommandCopy: () => false,
      })
    ).rejects.toThrow("copy-failed")
    await expect(
      writeTextWithFallback("https://example/sub", {})
    ).rejects.toThrow("copy-failed")
  })
})
