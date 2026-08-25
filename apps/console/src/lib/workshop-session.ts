/**
 * Workshop session: one deployer's live sitting at the Workshop.
 *
 * Owns `WorkshopFields` plus the in-progress job state — assembled diagnosis,
 * config selection, paste warnings as codes, Preview and version-probe
 * lifecycles with stale results dropped — behind one view + actions
 * interface. fetch, clipboard write, file save, and notify are injected
 * ports; Console chrome (locale, theme) — state and chrome bar — stays
 * outside with App. Empty
 * Conversion Service origin may adopt a Console origin through the
 * version-probe lifecycle.
 */

import {
  acl4ssrConfigUrl,
  configPresetOf,
  configSelectionId,
  type ConfigSelectionId,
} from "./acl4ssr-catalog.ts"
import {
  saveFileInBrowser,
  writeClipboardInBrowser,
} from "./browser-ports.ts"
import {
  createWorkshopProbe,
} from "./workshop-probe.ts"
import type { WorkshopFields } from "./persist.ts"
import {
  applyPaste,
  evaluateWorkshop,
  parseServiceOrigin,
  previewMediaType,
  runPreview,
  subscriptionPasteFrom,
  type PasteWarning,
  type PreviewState,
  type VersionState,
  type WorkshopFetch,
  type WorkshopView,
} from "./workshop.ts"

export type WorkshopNotice = "imported" | "copied" | "copy-failed"

/** Input snapshot of the source field a paste landed on. */
export type SourceSelection = {
  value: string
  selectionStart: number | null
  selectionEnd: number | null
}

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
  canonicalOrigin: string | null
  configSelection: ConfigSelectionId
  pasteWarnings: readonly PasteWarning[]
  version: VersionState
  preview: PreviewState
}

export type WorkshopSessionActions = {
  patch: (partial: Partial<WorkshopFields>) => void
  pasteIntoSource: (
    text: string,
    selection: SourceSelection
  ) => "imported" | "ignored"
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

/** Paste replaces a source field only when it is empty or fully selected. */
export function pasteReplacesValue(selection: SourceSelection): boolean {
  return (
    selection.value.trim().length === 0 ||
    (selection.selectionStart === 0 &&
      selection.selectionEnd === selection.value.length)
  )
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
  let pasteWarnings: readonly PasteWarning[] = []
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
  function setFields(
    next: WorkshopFields,
    nextPasteWarnings: readonly PasteWarning[] = []
  ) {
    fields = withSourceFloor(next)
    pasteWarnings = nextPasteWarnings
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
    const canonicalOrigin = parseServiceOrigin(fields.serviceOrigin)
    const configSelection = configSelectionId(
      configPresetOf(fields.configUrl),
      pickingCustom
    )
    view = {
      ...jobView,
      fields,
      canonicalOrigin,
      configSelection,
      pasteWarnings,
      version: probe.versionFor(canonicalOrigin),
      preview,
    }
    return view
  }

  const actions: WorkshopSessionActions = {
    patch: (partial) => {
      setFields({ ...fields, ...partial })
    },
    pasteIntoSource: (text, selection) => {
      const parsed = subscriptionPasteFrom(text)
      if (parsed === null || !pasteReplacesValue(selection)) {
        return "ignored"
      }
      pickingCustom = false
      setFields(applyPaste(fields, parsed), parsed.warnings)
      ports.notify?.("imported")
      return "imported"
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
        mediaType: previewMediaType(fields.target),
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
