import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { describe, expect, it } from "vitest"

describe("static headers and PWA", () => {
  it("sets Referrer-Policy and a Workshop CSP", () => {
    const text = readFileSync(
      resolve(import.meta.dirname, "../../public/_headers"),
      "utf8",
    )
    expect(text).toContain("Referrer-Policy: no-referrer")
    expect(text).toContain("default-src 'self'")
    expect(text).toContain("connect-src 'self' http: https:")
    expect(text).toContain("script-src 'self'")
  })

  it("does not navigate-fallback Conversion Service paths", () => {
    const text = readFileSync(
      resolve(import.meta.dirname, "../../vite.config.ts"),
      "utf8",
    )
    expect(text).toContain("navigateFallbackDenylist")
    expect(text).toContain("/^\\/sub(?:\\/|$)/")
    expect(text).toContain("/^\\/version(?:\\/|$)/")
  })
})
