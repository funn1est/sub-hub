/**
 * Workshop session: one deployer's live sitting at the Workshop.
 *
 * Owns `WorkshopFields` plus the in-progress job state — assembled diagnosis,
 * config selection, Preview and version-probe lifecycles with stale
 * results dropped — behind one view + actions interface. fetch, clipboard
 * write, file save, and notify are injected ports; Console chrome (locale,
 * theme) — state and chrome bar — stays outside with App. Empty
 * Conversion Service origin may adopt a Console origin through the
 * version-probe lifecycle.
 */

import {
  acl4ssrConfigUrl,
  configPresetOf,
  configSelectionId,
  type ConfigSelectionId,
} from "./acl4ssr-catalog.ts"
import { saveFileInBrowser, writeClipboardInBrowser } from "./browser-ports.ts"
import { createWorkshopProbe } from "./workshop-probe.ts"
import { subscriptionMediaType } from "./service-contract.ts"
import { runPreview, type PreviewState, type VersionState } from "./preview.ts"
import {
  evaluateWorkshop,
  parseServiceOrigin,
  type WorkshopFetch,
  type WorkshopFields,
  type WorkshopView,
} from "./workshop.ts"

export type WorkshopNotice = "copied" | "copy-failed"

export type SavedPreviewFile = {
  body: string
  mediaType: string
  filename: string
}

export type WorkshopSessionEnv = {
  pageHttps: boolean
  /** Console origin to try when Conversion Service origin is empty. */
  consoleOrigin?: string
}

export type WorkshopSessionPorts = {
  fetchImpl?: WorkshopFetch
  writeClipboard?: (text: string) => Promise<void>
  saveFile?: (file: SavedPreviewFile) => void
  notify?: (notice: WorkshopNotice) => void
}

export type WorkshopSessionView = WorkshopView & {
  fields: WorkshopFields
  configSelection: ConfigSelectionId
  version: VersionState
  preview: PreviewState
  previewReady: boolean
  serviceCollapsible: boolean
}

export type WorkshopSessionActions = {
  patch: (partial: Partial<WorkshopFields>) => void
  setSource: (index: number, value: string) => void
  setSourceFromPaste: (index: number, raw: string) => void
  addSource: () => void
  removeSource: (index: number) => void
  selectConfig: (id: ConfigSelectionId) => void
  editCustomConfigUrl: (value: string) => void
  blurOrigin: () => void
  preview: () => Promise<void>
  copy: () => Promise<void>
  download: () => void
}

export type WorkshopSession = {
  getView: () => WorkshopSessionView
  subscribe: (listener: () => void) => () => void
  actions: WorkshopSessionActions
}

export function createWorkshopSession(options: {
  initialFields: WorkshopFields
  env: WorkshopSessionEnv
  ports?: WorkshopSessionPorts
}): WorkshopSession {
  const { env } = options
  const ports = options.ports ?? {}
  const fetchImpl: WorkshopFetch =
    ports.fetchImpl ?? ((url, init) => fetch(url, init))
  const consoleOrigin = parseServiceOrigin(env.consoleOrigin ?? "")

  const listeners = new Set<() => void>()
  let fields = withSourceFloor(options.initialFields)
  let pickingCustom = false
  let preview: PreviewState = { status: "idle" }
  let previewSeq = 0
  let view: WorkshopSessionView | null = null

  const emit = () => {
    view = null
    for (const listener of [...listeners]) {
      listener()
    }
  }

  const probe = createWorkshopProbe({
    consoleOrigin,
    fetchImpl,
    fieldOrigin: () => parseServiceOrigin(fields.serviceOrigin),
    adoptOrigin: (origin) => {
      setFields({ ...fields, serviceOrigin: origin })
    },
    notify: emit,
  })

  /** Every conversion-field change invalidates Preview and re-aims the probe. */
  function setFields(next: WorkshopFields) {
    fields = withSourceFloor(next)
    previewSeq += 1
    preview = { status: "idle" }
    probe.ensure(fields.serviceOrigin)
    emit()
  }

  const getView = (): WorkshopSessionView => {
    if (view !== null) {
      return view
    }
    const jobView = evaluateWorkshop(fields)
    const configSelection = configSelectionId(
      configPresetOf(fields.configUrl),
      pickingCustom
    )
    view = {
      ...jobView,
      fields,
      configSelection,
      version: probe.versionFor(jobView.canonicalOrigin),
      preview,
      previewReady:
        jobView.assembled.previewable && preview.status !== "loading",
      serviceCollapsible:
        jobView.canonicalOrigin !== null && !jobView.tokenInvalid,
    }
    return view
  }

  const actions: WorkshopSessionActions = {
    patch: (partial) => {
      setFields({ ...fields, ...partial })
    },
    setSource: (index, value) => {
      if (index < 0 || index >= fields.sources.length) {
        return
      }
      const sources = fields.sources.slice()
      sources[index] = value
      setFields({ ...fields, sources })
    },
    setSourceFromPaste: (index, raw) => {
      if (index < 0 || index >= fields.sources.length) {
        return
      }
      const pieces = raw
        .split(/\r\n|\n|\|/)
        .map((piece) => piece.trim())
        .filter((piece) => piece.length > 0)
      if (pieces.length <= 1) {
        const sources = fields.sources.slice()
        sources[index] = pieces[0] ?? ""
        setFields({ ...fields, sources })
        return
      }
      const sources = fields.sources.slice()
      sources.splice(index, 1, ...pieces)
      setFields({ ...fields, sources })
    },
    addSource: () => {
      setFields({ ...fields, sources: [...fields.sources, ""] })
    },
    removeSource: (index) => {
      if (
        fields.sources.length <= 1 ||
        index < 0 ||
        index >= fields.sources.length
      ) {
        return
      }
      setFields({
        ...fields,
        sources: fields.sources.filter((_, item) => item !== index),
      })
    },
    selectConfig: (id) => {
      if (id === "custom") {
        pickingCustom = true
        emit()
        return
      }
      pickingCustom = false
      setFields({
        ...fields,
        configUrl: id === "none" ? "" : acl4ssrConfigUrl(id),
      })
    },
    editCustomConfigUrl: (value) => {
      pickingCustom = configPresetOf(value).kind === "custom"
      setFields({ ...fields, configUrl: value })
    },
    blurOrigin: () => {
      const canonical = parseServiceOrigin(fields.serviceOrigin)
      if (canonical !== null && canonical !== fields.serviceOrigin) {
        setFields({ ...fields, serviceOrigin: canonical })
      }
    },
    preview: async () => {
      const current = getView()
      if (
        current.assembled.url === null ||
        !current.assembled.previewable ||
        preview.status === "loading"
      ) {
        return
      }
      previewSeq += 1
      const seq = previewSeq
      preview = { status: "loading" }
      emit()
      const outcome = await runPreview({
        url: current.assembled.url,
        target: fields.target,
        pageHttps: env.pageHttps,
        fetchImpl,
      })
      if (seq !== previewSeq) {
        return
      }
      preview = outcome
      emit()
    },
    copy: async () => {
      const url = getView().assembled.url
      if (url === null) {
        return
      }
      const write = ports.writeClipboard ?? writeClipboardInBrowser
      try {
        await write(url)
        ports.notify?.("copied")
      } catch {
        ports.notify?.("copy-failed")
      }
    },
    download: () => {
      if (preview.status !== "done" || preview.httpStatus !== 200) {
        return
      }
      const save = ports.saveFile ?? saveFileInBrowser
      save({
        body: preview.body,
        mediaType: subscriptionMediaType(fields.target),
        filename: preview.filename,
      })
    },
  }

  probe.ensure(fields.serviceOrigin)

  return {
    getView,
    subscribe: (listener) => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    actions,
  }
}

function withSourceFloor(fields: WorkshopFields): WorkshopFields {
  return fields.sources.length > 0 ? fields : { ...fields, sources: [""] }
}
