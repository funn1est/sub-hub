import { describe, expect, it } from "vitest"

import {
  classifyFetchFailure,
  classifyPreviewBody,
  classifyVersionBody,
  fallbackDownloadName,
  filenameFromDisposition,
  PREVIEW_VIEW_LIMIT_BYTES,
  truncatePreviewBody,
} from "./preview.ts"

describe("classifyVersionBody", () => {
  it("accepts the Sub Hub version line and rejects other bodies", () => {
    expect(classifyVersionBody("sub-hub v0.1.0 backend")).toBe("sub-hub")
    expect(classifyVersionBody("sub-hub v1.2.3 backend")).toBe("sub-hub")
    expect(classifyVersionBody("nginx")).toBe("other")
    expect(classifyVersionBody("Unauthorized!")).toBe("other")
  })
})

describe("classifyPreviewBody", () => {
  it("maps exact English contract bodies and leaves other HTTP as raw", () => {
    expect(classifyPreviewBody(400, "Invalid target!")).toEqual({
      kind: "known-error",
      body: "Invalid target!",
    })
    expect(classifyPreviewBody(401, "Unauthorized!")).toEqual({
      kind: "known-error",
      body: "Unauthorized!",
    })
    expect(classifyPreviewBody(200, "proxies:\n")).toEqual({ kind: "ok" })
    expect(classifyPreviewBody(418, "teapot")).toEqual({ kind: "http" })
  })
})

describe("classifyFetchFailure", () => {
  it("does not pretend a CORS or mixed-content failure is 401", () => {
    expect(
      classifyFetchFailure({
        pageHttps: true,
        serviceOrigin: "http://example.com",
      }),
    ).toBe("mixed-content")
    expect(
      classifyFetchFailure({
        pageHttps: true,
        serviceOrigin: "http://127.0.0.1:25500",
      }),
    ).toBe("local-network")
    expect(
      classifyFetchFailure({
        pageHttps: true,
        serviceOrigin: "https://sub-hub.example",
      }),
    ).toBe("cors-or-network")
  })
})

describe("truncatePreviewBody", () => {
  it("keeps bodies at the view cap and marks overflow", () => {
    const exact = "n".repeat(PREVIEW_VIEW_LIMIT_BYTES)
    expect(truncatePreviewBody(exact)).toEqual({
      text: exact,
      truncated: false,
    })

    const over = `${exact}!`
    const truncated = truncatePreviewBody(over)
    expect(truncated.truncated).toBe(true)
    expect(new TextEncoder().encode(truncated.text).length).toBe(
      PREVIEW_VIEW_LIMIT_BYTES,
    )
    expect(truncated.text.endsWith("!")).toBe(false)
  })
})

describe("download filename", () => {
  it("prefers content-disposition and falls back to sub-hub-<target>.<ext>", () => {
    expect(
      filenameFromDisposition(
        'attachment; filename="sub-hub-mihomo.yaml"',
      ),
    ).toBe("sub-hub-mihomo.yaml")
    expect(fallbackDownloadName("clash")).toBe("sub-hub-clash.yaml")
    expect(fallbackDownloadName("mihomo")).toBe("sub-hub-mihomo.yaml")
    expect(fallbackDownloadName("quanx")).toBe("sub-hub-quanx.conf")
    expect(fallbackDownloadName("singbox")).toBe("sub-hub-singbox.json")
    expect(fallbackDownloadName("loon")).toBe("sub-hub-loon.conf")
    expect(fallbackDownloadName("egern")).toBe("sub-hub-egern.yaml")
  })
})
