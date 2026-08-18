import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { describe, expect, it } from "vitest"

describe("Pages headers", () => {
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
})
