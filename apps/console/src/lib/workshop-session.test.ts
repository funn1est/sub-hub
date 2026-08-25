import { describe, expect, it } from "vitest"

import { acl4ssrConfigUrl } from "./acl4ssr-catalog.ts"
import type { WorkshopFields } from "./persist.ts"
import {
  createWorkshopSession,
  pasteReplacesValue,
  type SavedPreviewFile,
  type WorkshopNotice,
  type WorkshopSessionPorts,
} from "./workshop-session.ts"

const VLESS =
  "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"
const VLESS_ENCODED =
  "vless%3A%2F%2F01234567-89ab-cdef-0123-456789abcdef%40example.com%3A443%23Alpha"
const ORIGIN = "http://127.0.0.1:25500"
const VERSION_OK = "sub-hub v0.1.0 backend"

function fields(overrides: Partial<WorkshopFields> = {}): WorkshopFields {
  return {
    serviceOrigin: "",
    accessToken: "",
    sources: [VLESS],
    target: "clash",
    configUrl: "",
    appendInfo: true,
    ...overrides,
  }
}

type FakeResponse = {
  status: number
  text: () => Promise<string>
  headers: { get: (name: string) => string | null }
}

function response(
  status: number,
  body: string,
  headers: Record<string, string> = {}
): FakeResponse {
  const map = new Map(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])
  )
  return {
    status,
    text: () => Promise.resolve(body),
    headers: { get: (name) => map.get(name.toLowerCase()) ?? null },
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((ready) => {
    resolve = ready
  })
  return { promise, resolve }
}

function flush(): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, 0)
  })
}

function makeSession(input: {
  fields?: Partial<WorkshopFields>
  fetch?: (url: string) => FakeResponse | Promise<FakeResponse>
  ports?: WorkshopSessionPorts
  consoleOrigin?: string
}) {
  const notices: WorkshopNotice[] = []
  const calls: string[] = []
  const session = createWorkshopSession({
    initialFields: fields(input.fields),
    env: { pageHttps: false, consoleOrigin: input.consoleOrigin },
    ports: {
      fetchImpl: (url) => {
        calls.push(url)
        const handler = input.fetch ?? (() => response(200, VERSION_OK))
        return Promise.resolve(handler(url))
      },
      notify: (notice) => notices.push(notice),
      ...input.ports,
    },
  })
  return { session, notices, calls, view: () => session.getView() }
}

describe("pasteReplacesValue", () => {
  it("replaces only an empty or fully selected field", () => {
    expect(
      pasteReplacesValue({
        value: "",
        selectionStart: null,
        selectionEnd: null,
      })
    ).toBe(true)
    expect(
      pasteReplacesValue({ value: "  ", selectionStart: 1, selectionEnd: 1 })
    ).toBe(true)
    expect(
      pasteReplacesValue({ value: "keep", selectionStart: 0, selectionEnd: 4 })
    ).toBe(true)
    expect(
      pasteReplacesValue({ value: "keep", selectionStart: 0, selectionEnd: 2 })
    ).toBe(false)
    expect(
      pasteReplacesValue({
        value: "keep",
        selectionStart: null,
        selectionEnd: null,
      })
    ).toBe(false)
  })
})

describe("createWorkshopSession", () => {
  it("imports a pasted Subscription URL, keeps warning codes, and notifies", () => {
    const { session, notices, view } = makeSession({
      fields: { sources: [""] },
    })
    const outcome = session.actions.pasteIntoSource(
      `${ORIGIN}/sub?target=loon&url=${VLESS_ENCODED}&filename=x`,
      { value: "", selectionStart: null, selectionEnd: null }
    )
    expect(outcome).toBe("imported")
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
    expect(view().fields.target).toBe("loon")
    expect(view().fields.sources).toEqual([VLESS])
    expect(view().pasteWarnings).toEqual(["unknown-keys"])
    expect(notices).toEqual(["imported"])
    expect(view().preview.status).toBe("idle")

    session.actions.patch({ target: "clash" })
    expect(view().pasteWarnings).toEqual([])
  })

  it("ignores provider sources and unselected filled fields", () => {
    const { session, notices, view } = makeSession({})
    expect(
      session.actions.pasteIntoSource(
        "https://provider.example/sub?token=abc",
        { value: "", selectionStart: null, selectionEnd: null }
      )
    ).toBe("ignored")
    expect(
      session.actions.pasteIntoSource(
        `${ORIGIN}/sub?target=clash&url=${VLESS_ENCODED}`,
        { value: "existing", selectionStart: 2, selectionEnd: 4 }
      )
    ).toBe("ignored")
    expect(view().fields.sources).toEqual([VLESS])
    expect(notices).toEqual([])
  })

  it("previews the Subscription URL and consumes skip headers", async () => {
    const { session, view } = makeSession({
      fields: { serviceOrigin: ORIGIN },
      fetch: (url) =>
        url.endsWith("/version")
          ? response(200, VERSION_OK)
          : response(200, "proxies: []", {
              "x-subconverter-skipped": "parse=1;capability=2;name=3",
              "content-disposition": 'attachment; filename="sub.yaml"',
            }),
    })
    await session.actions.preview()
    const preview = view().preview
    expect(preview.status).toBe("done")
    if (preview.status !== "done") {
      return
    }
    expect(preview.httpStatus).toBe(200)
    expect(preview.kind).toEqual({ kind: "ok" })
    expect(preview.skipped).toEqual({ parse: 1, capability: 2, name: 3 })
    expect(preview.filename).toBe("sub.yaml")
  })

  it("resets Preview when fields change and drops the stale in-flight result", async () => {
    const gate = deferred<FakeResponse>()
    const { session, view } = makeSession({
      fields: { serviceOrigin: ORIGIN },
      fetch: (url) =>
        url.endsWith("/version") ? response(200, VERSION_OK) : gate.promise,
    })
    const running = session.actions.preview()
    expect(view().preview.status).toBe("loading")
    expect(view().assembled.previewable && view().preview.status !== "loading").toBe(
      false
    )
    session.actions.patch({ target: "loon" })
    expect(view().preview.status).toBe("idle")
    gate.resolve(response(200, "proxies: []"))
    await running
    expect(view().preview.status).toBe("idle")
    expect(view().assembled.previewable && view().preview.status !== "loading").toBe(
      true
    )
  })

  it("does not start Preview when the Subscription URL is incomplete", async () => {
    const { session, view, calls } = makeSession({
      fields: { serviceOrigin: "" },
    })
    await session.actions.preview()
    expect(view().preview.status).toBe("idle")
    expect(calls).toEqual([])
  })

  it("walks config selection across none, preset, and custom", () => {
    const { session, view } = makeSession({})
    session.actions.selectConfig("ACL4SSR_Online.ini")
    expect(view().fields.configUrl).toBe(acl4ssrConfigUrl("ACL4SSR_Online.ini"))
    expect(view().configSelection).toBe("ACL4SSR_Online.ini")
    expect(view().configSelection === "custom").toBe(false)

    session.actions.selectConfig("custom")
    expect(view().fields.configUrl).toBe(acl4ssrConfigUrl("ACL4SSR_Online.ini"))
    expect(view().configSelection === "custom").toBe(true)

    session.actions.editCustomConfigUrl("https://example.com/custom.ini")
    expect(view().configSelection).toBe("custom")

    session.actions.editCustomConfigUrl(
      acl4ssrConfigUrl("ACL4SSR_Online_Mini.ini")
    )
    expect(view().configSelection).toBe("ACL4SSR_Online_Mini.ini")

    session.actions.selectConfig("none")
    expect(view().fields.configUrl).toBe("")
    expect(view().configSelection).toBe("none")
  })

  it("probes /version for the canonical origin and drops stale probes", async () => {
    const first = deferred<FakeResponse>()
    const { session, view, calls } = makeSession({
      fetch: (url) =>
        url === `${ORIGIN}/version` ? first.promise : response(200, VERSION_OK),
    })
    expect(view().version.status).toBe("idle")

    session.actions.patch({ serviceOrigin: `${ORIGIN}/` })
    expect(view().version.status).toBe("checking")
    expect(calls).toEqual([`${ORIGIN}/version`])

    session.actions.blurOrigin()
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
    expect(calls).toEqual([`${ORIGIN}/version`])

    session.actions.patch({ serviceOrigin: "https://other.example" })
    first.resolve(response(200, VERSION_OK))
    await flush()
    expect(view().version).toEqual({ status: "ok", body: VERSION_OK })
    expect(calls).toEqual([
      `${ORIGIN}/version`,
      "https://other.example/version",
    ])

    session.actions.patch({ serviceOrigin: "" })
    expect(view().version.status).toBe("idle")
  })

  it("does not adopt a later origin after the field is filled", () => {
    const { session, view } = makeSession({})
    session.actions.patch({ serviceOrigin: ORIGIN })
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
    session.actions.patch({ serviceOrigin: "https://other.example" })
    expect(view().fields.serviceOrigin).toBe("https://other.example")
  })

  it("adopts console origin after a successful same-origin version probe", async () => {
    const { view, calls } = makeSession({
      fields: { serviceOrigin: "" },
      consoleOrigin: ORIGIN,
    })
    expect(view().fields.serviceOrigin).toBe("")
    expect(view().version.status).toBe("idle")
    expect(calls).toEqual([`${ORIGIN}/version`])
    await flush()
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
    expect(view().version).toEqual({ status: "ok", body: VERSION_OK })
    expect(view().pasteWarnings).toEqual([])
    expect(view().preview.status).toBe("idle")
    expect(calls).toEqual([`${ORIGIN}/version`])
  })

  it("discovers console origin again after the origin field is cleared", async () => {
    const { session, view, calls } = makeSession({
      fields: { serviceOrigin: "" },
      consoleOrigin: ORIGIN,
    })
    await flush()
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
    session.actions.patch({ serviceOrigin: "" })
    expect(view().fields.serviceOrigin).toBe("")
    expect(view().version.status).toBe("idle")
    expect(calls).toEqual([`${ORIGIN}/version`, `${ORIGIN}/version`])
    await flush()
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
  })

  it("does not adopt console origin when the version probe fails", async () => {
    const unreachable = makeSession({
      fields: { serviceOrigin: "" },
      consoleOrigin: ORIGIN,
      fetch: () => Promise.reject(new Error("offline")),
    })
    await flush()
    expect(unreachable.view().fields.serviceOrigin).toBe("")
    expect(unreachable.view().version.status).toBe("idle")
    expect(unreachable.calls).toEqual([`${ORIGIN}/version`])

    const other = makeSession({
      fields: { serviceOrigin: "" },
      consoleOrigin: ORIGIN,
      fetch: () => response(200, "nginx"),
    })
    await flush()
    expect(other.view().fields.serviceOrigin).toBe("")
    expect(other.view().version.status).toBe("idle")
  })

  it("ignores a late same-origin guess after the origin field is filled", async () => {
    const gate = deferred<FakeResponse>()
    const { session, view, calls } = makeSession({
      fields: { serviceOrigin: "" },
      consoleOrigin: ORIGIN,
      fetch: (url) =>
        url === `${ORIGIN}/version` ? gate.promise : response(200, VERSION_OK),
    })
    session.actions.patch({ serviceOrigin: "https://other.example" })
    gate.resolve(response(200, VERSION_OK))
    await flush()
    expect(view().fields.serviceOrigin).toBe("https://other.example")
    expect(view().version).toEqual({ status: "ok", body: VERSION_OK })
    expect(calls).toEqual([
      `${ORIGIN}/version`,
      "https://other.example/version",
    ])
  })

  it("does not guess when Conversion Service origin is already set", async () => {
    const { view, calls } = makeSession({
      fields: { serviceOrigin: ORIGIN },
      consoleOrigin: "https://other.example",
    })
    await flush()
    expect(view().fields.serviceOrigin).toBe(ORIGIN)
    expect(calls).toEqual([`${ORIGIN}/version`])
  })

  it("notifies copied or copy-failed from the clipboard port", async () => {
    const wrote: string[] = []
    const ok = makeSession({
      fields: { serviceOrigin: ORIGIN },
      ports: {
        writeClipboard: (text) => {
          wrote.push(text)
          return Promise.resolve()
        },
      },
    })
    await ok.session.actions.copy()
    expect(wrote).toEqual([`${ORIGIN}/sub?target=clash&url=${VLESS_ENCODED}`])
    expect(ok.notices).toEqual(["copied"])

    const failing = makeSession({
      fields: { serviceOrigin: ORIGIN },
      ports: { writeClipboard: () => Promise.reject(new Error("denied")) },
    })
    await failing.session.actions.copy()
    expect(failing.notices).toEqual(["copy-failed"])

    const empty = makeSession({ fields: { serviceOrigin: "" } })
    await empty.session.actions.copy()
    expect(empty.notices).toEqual([])
  })

  it("downloads only a 200 Preview document through the save port", async () => {
    const saved: SavedPreviewFile[] = []
    const { session } = makeSession({
      fields: { serviceOrigin: ORIGIN, target: "singbox" },
      fetch: (url) =>
        url.endsWith("/version")
          ? response(200, VERSION_OK)
          : response(200, "{}", {
              "content-disposition": 'attachment; filename="sub.json"',
            }),
      ports: { saveFile: (file) => saved.push(file) },
    })
    session.actions.download()
    expect(saved).toEqual([])
    await session.actions.preview()
    session.actions.download()
    expect(saved).toEqual([
      {
        body: "{}",
        mediaType: "application/json;charset=utf-8",
        filename: "sub.json",
      },
    ])

    const failed: SavedPreviewFile[] = []
    const error = makeSession({
      fields: { serviceOrigin: ORIGIN },
      fetch: (url) =>
        url.endsWith("/version")
          ? response(200, VERSION_OK)
          : response(500, "Internal Server Error"),
      ports: { saveFile: (file) => failed.push(file) },
    })
    await error.session.actions.preview()
    error.session.actions.download()
    expect(failed).toEqual([])
  })

  it("keeps one source row after clearing", () => {
    const { session, view } = makeSession({})
    session.actions.patch({ sources: [] })
    expect(view().fields.sources).toEqual([""])
  })
})
