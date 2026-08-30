import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

import {
  EXPOSED_HEADERS,
  GET_TARGET_LIMIT_BYTES,
  KNOWN_SERVICE_ERRORS,
  QUERY_KEYS,
  SKIPPED_HEADER,
  TARGETS,
  VERSION_BODY,
  VERSION_PATH,
  encodeSubGetTarget,
  fallbackDownloadName,
  isQueryKey,
  isTarget,
  parseFilenameStem,
  parseSkippedHeader,
  percentDecodeValue,
  subscriptionMediaType,
  type Target,
} from "./service-contract.ts"
import {
  filenameFromDisposition,
  parseSkippedFromHeaders,
} from "./preview.ts"
type GoldenContract = {
  targets: string[]
  queryKeys: string[]
  getTargetLimitBytes: number
  versionPath: string
  versionBodyPattern: string
  skippedHeader: string
  exposedHeaders: string[]
  errors: string[]
  filenames: Record<string, string>
  mediaTypes: Record<string, string>
  dispositions: Record<string, string>
  percentDecode: Array<{ encoded: string; decoded: string | null }>
  skipSamples: Array<{
    skipped: string
    counts: { parse: number; capability: number; name: number }
  }>
  skipRejects: string[]
}

async function loadContract(): Promise<GoldenContract> {
  const raw = await readFile(
    resolve(
      import.meta.dirname,
      "../../../../testdata/subscription-url/cases.json"
    ),
    "utf8"
  )
  return (JSON.parse(raw) as { contract: GoldenContract }).contract
}

describe("Conversion Service GET contract", () => {
  it("matches the shared golden tables", async () => {
    const contract = await loadContract()
    expect(TARGETS).toEqual(contract.targets)
    expect(isTarget("clash")).toBe(true)
    expect(isTarget("clashmeta")).toBe(false)
    expect(QUERY_KEYS).toEqual(contract.queryKeys)
    expect(isQueryKey("insert")).toBe(true)
    expect(isQueryKey("filename")).toBe(true)
    expect(GET_TARGET_LIMIT_BYTES).toBe(contract.getTargetLimitBytes)
    expect(KNOWN_SERVICE_ERRORS).toEqual(contract.errors)
    expect(SKIPPED_HEADER).toBe(contract.skippedHeader)
    expect(EXPOSED_HEADERS).toEqual(contract.exposedHeaders)
    expect(VERSION_PATH).toBe(contract.versionPath)
    expect(VERSION_BODY.source).toBe(contract.versionBodyPattern)
    expect(fallbackDownloadName("clash")).toBe(fallbackDownloadName("mihomo"))
    for (const target of contract.targets) {
      expect(subscriptionMediaType(target as Target)).toBe(
        contract.mediaTypes[target]
      )
      expect(fallbackDownloadName(target as Target)).toBe(
        contract.filenames[target]
      )
      expect(filenameFromDisposition(contract.dispositions[target])).toBe(
        contract.filenames[target]
      )
    }
    for (const sample of contract.skipSamples) {
      expect(parseSkippedHeader(sample.skipped)).toEqual(sample.counts)
      expect(
        parseSkippedFromHeaders([
          { name: SKIPPED_HEADER, value: sample.skipped },
        ])
      ).toEqual(sample.counts)
    }
    for (const rejected of contract.skipRejects) {
      expect(parseSkippedHeader(rejected)).toBeNull()
    }
    for (const sample of contract.percentDecode) {
      expect(percentDecodeValue(sample.encoded)).toBe(sample.decoded)
    }
  })

  it("encodes request-target without insert and keeps a literal plus", () => {
    const getTarget = encodeSubGetTarget({
      accessToken: "",
      target: "clash",
      sources: ["ss://aes-128-gcm:p+ss@example.com:8388#Plus"],
      configUrl: "",
      appendInfo: true,
    })
    expect(getTarget).toBe(
      "/sub?target=clash&url=ss%3A%2F%2Faes-128-gcm%3Ap%2Bss%40example.com%3A8388%23Plus"
    )
    expect(getTarget).not.toContain("insert")
  })

  it("accepts a download-name stem and rejects path characters", () => {
    expect(parseFilenameStem("airport")).toBe("airport")
    expect(parseFilenameStem("机场")).toBe("机场")
    expect(parseFilenameStem("")).toBeNull()
    expect(parseFilenameStem("..")).toBeNull()
    expect(parseFilenameStem("a/b")).toBeNull()
    expect(parseFilenameStem("a".repeat(65))).toBeNull()
  })
})
