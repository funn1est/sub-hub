import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { describe, expect, it } from "vitest"

function headerBlocks(text: string): Map<string, string[]> {
  const blocks = new Map<string, string[]>()
  let selector: string | undefined
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd()
    if (line.trim() === "" || line.trimStart().startsWith("#")) {
      continue
    }
    if (!/^[ \t]/.test(line)) {
      selector = line.trim()
      blocks.set(selector, [])
      continue
    }
    if (selector === undefined) {
      throw new Error(`header line without a selector: ${line}`)
    }
    blocks.get(selector)?.push(line.trim())
  }
  return blocks
}

describe("static headers and PWA", () => {
  const text = readFileSync(
    resolve(import.meta.dirname, "../../public/_headers"),
    "utf8"
  )
  const blocks = headerBlocks(text)

  it("sets Referrer-Policy and a Workshop CSP", () => {
    const globalHeaders = blocks.get("/*") ?? []
    expect(globalHeaders).toContain("Referrer-Policy: no-referrer")
    expect(globalHeaders).toContain(
      "Content-Security-Policy: default-src 'self'; connect-src 'self' http: https:; script-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    )
    expect(globalHeaders).toContain("X-Content-Type-Options: nosniff")
    expect(globalHeaders).toContain("X-Frame-Options: DENY")
  })

  it("does not long-cache HTML; hashed assets are immutable", () => {
    const globalHeaders = blocks.get("/*") ?? []
    expect(globalHeaders.join("\n")).not.toMatch(/max-age=31536000/)
    expect(blocks.get("/assets/*")).toEqual([
      "Cache-Control: public, max-age=31536000, immutable",
    ])
    expect(blocks.get("/workbox-*")).toEqual([
      "Cache-Control: public, max-age=31536000, immutable",
    ])
  })

  it("asks crawlers not to index workers.dev hostnames", () => {
    const noindex = ["X-Robots-Tag: noindex"]
    expect(blocks.get("https://:name.:subdomain.workers.dev/*")).toEqual(
      noindex
    )
    expect(
      blocks.get("https://:version.:name.:subdomain.workers.dev/*")
    ).toEqual(noindex)
  })

  it("does not navigate-fallback Conversion Service paths", () => {
    const text = readFileSync(
      resolve(import.meta.dirname, "../../vite.config.ts"),
      "utf8"
    )
    expect(text).toContain("navigateFallbackDenylist")
    expect(text).toContain("/^\\/sub(?:\\/|$)/")
    expect(text).toContain("/^\\/version(?:\\/|$)/")
  })
})
