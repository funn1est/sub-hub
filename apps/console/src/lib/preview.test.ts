import { describe, expect, it } from "vitest"

import {
  fallbackDownloadName,
  parseOmittedRulesHeader,
  parseSkippedHeader,
} from "./service-contract.ts"
import {
  classifyFetchFailure,
  classifyPreviewBody,
  classifyVersionBody,
  filenameFromDisposition,
  isLoopbackHost,
  PREVIEW_VIEW_LIMIT_BYTES,
  readSubGetHeaders,
  runPreview,
  runVersionProbe,
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

describe("isLoopbackHost", () => {
  it("recognizes localhost and loopback literals", () => {
    expect(isLoopbackHost("localhost")).toBe(true)
    expect(isLoopbackHost("127.0.0.1")).toBe(true)
    expect(isLoopbackHost("::1")).toBe(true)
    expect(isLoopbackHost("[::1]")).toBe(true)
    expect(isLoopbackHost("example.com")).toBe(false)
  })
})

describe("runVersionProbe", () => {
  it("classifies a Conversion Service version body", async () => {
    const probe = await runVersionProbe({
      origin: "http://127.0.0.1:25500",
      fetchImpl: async () => ({
        text: async () => "sub-hub v0.1.0 backend",
      }),
    })
    expect(probe).toEqual({ status: "ok", body: "sub-hub v0.1.0 backend" })
  })

  it("treats a foreign body as other and a throw as unreachable", async () => {
    await expect(
      runVersionProbe({
        origin: "http://127.0.0.1:25500",
        fetchImpl: async () => ({ text: async () => "nginx" }),
      })
    ).resolves.toEqual({ status: "other" })
    await expect(
      runVersionProbe({
        origin: "http://127.0.0.1:25500",
        fetchImpl: async () => {
          throw new Error("network")
        },
      })
    ).resolves.toEqual({ status: "unreachable" })
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
      })
    ).toBe("mixed-content")
    expect(
      classifyFetchFailure({
        pageHttps: true,
        serviceOrigin: "http://127.0.0.1:25500",
      })
    ).toBe("local-network")
    expect(
      classifyFetchFailure({
        pageHttps: true,
        serviceOrigin: "https://sub-hub.example",
      })
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
      PREVIEW_VIEW_LIMIT_BYTES
    )
    expect(truncated.text.endsWith("!")).toBe(false)
  })
})

describe("parseSkippedHeader", () => {
  it("accepts the closed count grammar and rejects junk", () => {
    expect(parseSkippedHeader("parse=1;capability=4;name=0")).toEqual({
      parse: 1,
      capability: 4,
      name: 0,
    })
    expect(parseSkippedHeader(null)).toBeNull()
    expect(parseSkippedHeader("")).toBeNull()
    expect(parseSkippedHeader("parse=1")).toBeNull()
    expect(parseSkippedHeader("parse=01;capability=0;name=0")).toEqual({
      parse: 1,
      capability: 0,
      name: 0,
    })
  })
})

describe("parseOmittedRulesHeader", () => {
  it("summarizes lossy URL-REGEX=3", () => {
    expect(parseOmittedRulesHeader("lossy", "URL-REGEX=3")).toEqual({
      omittedUrlRegex: 3,
    })
  })

  it("returns null when either header is missing", () => {
    expect(parseOmittedRulesHeader(null, null)).toBeNull()
    expect(parseOmittedRulesHeader("lossy", null)).toBeNull()
    expect(parseOmittedRulesHeader(null, "URL-REGEX=3")).toBeNull()
    expect(parseOmittedRulesHeader("", "URL-REGEX=3")).toBeNull()
  })

  it("returns null for unknown result tokens or malformed omitted rules", () => {
    expect(parseOmittedRulesHeader("partial", "URL-REGEX=3")).toBeNull()
    expect(parseOmittedRulesHeader("lossy", "URL-REGEX=")).toBeNull()
    expect(parseOmittedRulesHeader("lossy", "URL-REGEX=-1")).toBeNull()
    expect(parseOmittedRulesHeader("lossy", "PROCESS-NAME=1")).toBeNull()
    expect(parseOmittedRulesHeader("lossy", "URL-REGEX=3;extra")).toBeNull()
    expect(parseOmittedRulesHeader("lossy", "url-regex=3")).toBeNull()
  })

  it("surfaces the summary on readSubGetHeaders without throwing on junk", () => {
    expect(
      readSubGetHeaders(
        {
          get: (name) => {
            if (name === "x-subconverter-result") {
              return "lossy"
            }
            if (name === "x-subconverter-omitted-rules") {
              return "URL-REGEX=3"
            }
            return null
          },
        },
        "clash"
      ).omitted
    ).toEqual({ omittedUrlRegex: 3 })
    expect(
      readSubGetHeaders(
        {
          get: (name) => {
            if (name === "x-subconverter-result") {
              return "nope"
            }
            if (name === "x-subconverter-omitted-rules") {
              return "garbage"
            }
            return null
          },
        },
        "clash"
      ).omitted
    ).toBeNull()
  })
})

describe("download filename", () => {
  it("prefers content-disposition and falls back to sub-hub-<target>.<ext>", () => {
    expect(
      filenameFromDisposition('attachment; filename="sub-hub-mihomo.yaml"')
    ).toBe("sub-hub-mihomo.yaml")
    expect(fallbackDownloadName("clash")).toBe("sub-hub-mihomo.yaml")
    expect(fallbackDownloadName("mihomo")).toBe("sub-hub-mihomo.yaml")
    expect(fallbackDownloadName("quanx")).toBe("sub-hub-quanx.conf")
    expect(fallbackDownloadName("singbox")).toBe("sub-hub-singbox.json")
    expect(fallbackDownloadName("loon")).toBe("sub-hub-loon.conf")
    expect(fallbackDownloadName("egern")).toBe("sub-hub-egern.yaml")
  })
})

describe("runPreview", () => {
  it("returns a done Preview from the Subscription URL GET", async () => {
    const outcome = await runPreview({
      url: "http://127.0.0.1:25500/sub?target=clash&url=vless://x",
      target: "clash",
      pageHttps: false,
      fetchImpl: async () => ({
        status: 200,
        text: async () => "mode: rule\n",
        headers: {
          get: (name: string) =>
            name === "content-disposition"
              ? 'attachment; filename="sub-hub-mihomo.yaml"'
              : null,
        },
      }),
    })
    expect(outcome).toEqual({
      status: "done",
      httpStatus: 200,
      kind: { kind: "ok" },
      headers: [
        {
          name: "content-disposition",
          value: 'attachment; filename="sub-hub-mihomo.yaml"',
        },
      ],
      skipped: null,
      omitted: null,
      body: "mode: rule\n",
      viewText: "mode: rule\n",
      truncated: false,
      filename: "sub-hub-mihomo.yaml",
    })
  })

  it("surfaces omitted URL-REGEX from lossy headers and keeps the raw headers", async () => {
    const outcome = await runPreview({
      url: "http://127.0.0.1:25500/sub?target=clash&url=vless://x",
      target: "clash",
      pageHttps: false,
      fetchImpl: async () => ({
        status: 200,
        text: async () => "mode: rule\n",
        headers: {
          get: (name: string) => {
            if (name === "x-subconverter-result") {
              return "lossy"
            }
            if (name === "x-subconverter-omitted-rules") {
              return "URL-REGEX=3"
            }
            return null
          },
        },
      }),
    })
    expect(outcome.status).toBe("done")
    if (outcome.status === "done") {
      expect(outcome.omitted).toEqual({ omittedUrlRegex: 3 })
      expect(outcome.headers).toEqual([
        { name: "x-subconverter-result", value: "lossy" },
        { name: "x-subconverter-omitted-rules", value: "URL-REGEX=3" },
      ])
    }
  })

  it("falls back to the Mihomo download name for the clash wire token", async () => {
    const outcome = await runPreview({
      url: "http://127.0.0.1:25500/sub?target=clash&url=vless://x",
      target: "clash",
      pageHttps: false,
      fetchImpl: async () => ({
        status: 200,
        text: async () => "proxies:\n",
        headers: { get: () => null },
      }),
    })
    expect(outcome.status).toBe("done")
    if (outcome.status === "done") {
      expect(outcome.filename).toBe("sub-hub-mihomo.yaml")
    }
  })

  it("classifies a thrown fetch as unreachable", async () => {
    const outcome = await runPreview({
      url: "http://127.0.0.1:25500/sub?target=clash&url=vless://x",
      target: "clash",
      pageHttps: true,
      fetchImpl: async () => {
        throw new TypeError("Failed to fetch")
      },
    })
    expect(outcome).toEqual({
      status: "unreachable",
      cause: "local-network",
    })
  })
})
