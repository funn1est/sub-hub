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
  type Acl4ssrConfigFile,
} from "./acl4ssr-catalog.ts"
import { writeTextWithFallback } from "./clipboard.ts"
import type { WorkshopFields } from "./persist.ts"
import {
  applyPaste,
  clashInstallUrl,
  evaluateWorkshop,
  parseServiceOrigin,
  previewMediaType,
  runPreview,
  runVersionProbe,
  subscriptionPasteFrom,
  type PasteWarning,
  type PreviewState,
  type VersionProbe,
  type WorkshopView,
} from "./workshop.ts"

export type VersionState =
  { status: "idle" } | { status: "checking" } | VersionProbe

export type WorkshopNotice = "imported" | "copied" | "copy-failed"

/** Input snapshot of the source field a paste landed on. */
export type SourceSelection = {
  value: string
  selectionStart: number | null
  selectionEnd: number | null
}

export type ConfigSelectionId = "none" | "custom" | Acl4ssrConfigFile

export type SavedPreviewFile = {
  body: string
  mediaType: string
  filename: string
}

type SessionFetch = (
  url: string,
  init?: { signal?: AbortSignal }
) => Promise<{
  status: number
  text: () => Promise<string>
  headers: { get: (name: string) => string | null }
}>

export type WorkshopSessionEnv = {
  pageHttps: boolean
  /** Console origin to try when Conversion Service origin is empty. */
  consoleOrigin?: string
}

export type WorkshopSessionPorts = {
  fetchImpl?: SessionFetch
  writeClipboard?: (text: string) => Promise<void>
  saveFile?: (file: SavedPreviewFile) => void
  notify?: (notice: WorkshopNotice) => void
}

export type WorkshopSessionView = WorkshopView & {
  fields: WorkshopFields
  canonicalOrigin: string | null
  canCollapseService: boolean
  configSelection: ConfigSelectionId
  showCustomConfigField: boolean
  pasteWarnings: readonly PasteWarning[]
  version: VersionState
  preview: PreviewState
  previewEnabled: boolean
  clashInstallHref: string | null
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
  adoptOrigin: (origin: string) => void
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
  const fetchImpl: SessionFetch =
    ports.fetchImpl ?? ((url, init) => fetch(url, init))
  const consoleOrigin = parseServiceOrigin(env.consoleOrigin ?? "")

  const listeners = new Set<() => void>()
  let fields = withSourceFloor(options.initialFields)
  let pickingCustom = false
  let pasteWarnings: readonly PasteWarning[] = []
  let preview: PreviewState = { status: "idle" }
  let previewSeq = 0
  let probe: { origin: string; state: VersionProbe } | null = null
  let probeSeq = 0
  let probeController: AbortController | null = null
  let probeInFlight: string | null = null
  let view: WorkshopSessionView | null = null

  const emit = () => {
    view = null
    for (const listener of [...listeners]) {
      listener()
    }
  }

  const finishProbe = (origin: string, state: VersionProbe) => {
    probeInFlight = null
    probeController = null
    const fieldOrigin = parseServiceOrigin(fields.serviceOrigin)
    if (fieldOrigin === null) {
      if (state.status !== "ok" || origin !== consoleOrigin) {
        return
      }
      probe = { origin, state }
      setFields({ ...fields, serviceOrigin: origin })
      return
    }
    if (fieldOrigin === origin) {
      probe = { origin, state }
      emit()
    }
  }

  const startProbe = (origin: string) => {
    if (probe?.origin === origin || probeInFlight === origin) {
      return
    }
    probeSeq += 1
    const seq = probeSeq
    probeController?.abort()
    const controller = new AbortController()
    probeController = controller
    probeInFlight = origin
    void runVersionProbe({ origin, signal: controller.signal, fetchImpl }).then(
      (state) => {
        if (seq !== probeSeq) {
          return
        }
        finishProbe(origin, state)
      }
    )
  }

  const ensureProbe = () => {
    const origin = parseServiceOrigin(fields.serviceOrigin)
    if (origin === null) {
      probeSeq += 1
      probeController?.abort()
      probeController = null
      probeInFlight = null
      return
    }
    startProbe(origin)
  }

  /** Every conversion-field change invalidates Preview and re-aims the probe. */
  const setFields = (next: WorkshopFields) => {
    fields = withSourceFloor(next)
    previewSeq += 1
    preview = { status: "idle" }
    ensureProbe()
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
      canCollapseService: canonicalOrigin !== null && !jobView.tokenInvalid,
      configSelection,
      showCustomConfigField: configSelection === "custom",
      pasteWarnings,
      version:
        canonicalOrigin === null
          ? { status: "idle" }
          : probe === null || probe.origin !== canonicalOrigin
            ? { status: "checking" }
            : probe.state,
      preview,
      previewEnabled:
        jobView.assembled.previewable && preview.status !== "loading",
      clashInstallHref:
        jobView.assembled.clashInstall && jobView.assembled.url !== null
          ? clashInstallUrl(jobView.assembled.url)
          : null,
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
      pasteWarnings = parsed.warnings
      setFields(applyPaste(fields, parsed))
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
    adoptOrigin: (origin) => {
      if (fields.serviceOrigin.trim() !== "") {
        return
      }
      setFields({ ...fields, serviceOrigin: origin })
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

  ensureProbe()
  if (
    parseServiceOrigin(fields.serviceOrigin) === null &&
    consoleOrigin !== null
  ) {
    startProbe(consoleOrigin)
  }

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

function writeClipboardInBrowser(text: string): Promise<void> {
  const clipboard = navigator.clipboard
  return writeTextWithFallback(text, {
    writeText:
      clipboard === undefined ? undefined : clipboard.writeText.bind(clipboard),
    execCommandCopy,
  })
}

function execCommandCopy(text: string): boolean {
  const textarea = document.createElement("textarea")
  textarea.value = text
  textarea.setAttribute("readonly", "")
  textarea.style.position = "fixed"
  textarea.style.top = "0"
  textarea.style.left = "0"
  textarea.style.width = "1px"
  textarea.style.height = "1px"
  textarea.style.padding = "0"
  textarea.style.border = "none"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  textarea.setSelectionRange(0, text.length)
  try {
    return document.execCommand("copy")
  } finally {
    document.body.removeChild(textarea)
  }
}

function saveFileInBrowser(file: SavedPreviewFile): void {
  const blob = new Blob([file.body], { type: file.mediaType })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = objectUrl
  link.download = file.filename
  link.rel = "noopener"
  link.style.display = "none"
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 2500)
}
