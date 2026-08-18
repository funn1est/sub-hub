import { describe, expect, it } from "vitest"

import { KNOWN_SERVICE_ERRORS } from "./workshop.ts"
import { knownErrorTitle } from "./i18n.ts"

describe("known Conversion Service errors", () => {
  it("has a distinct zh and en title for every exact English body", () => {
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

    for (const body of KNOWN_SERVICE_ERRORS) {
      const zh = knownErrorTitle("zh", body)
      const en = knownErrorTitle("en", body)
      expect(zh.length).toBeGreaterThan(0)
      expect(en.length).toBeGreaterThan(0)
      expect(zh).not.toBe(en)
      expect(zh).not.toBe(body)
    }
  })
})
