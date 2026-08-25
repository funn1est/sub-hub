import {
  parseServiceOrigin,
  runVersionProbe,
  type VersionProbe,
  type VersionState,
  type WorkshopFetch,
} from "./workshop.ts"

export type ProbeRun =
  | { kind: "idle" }
  | {
      kind: "checking"
      target: string
      controller: AbortController
    }
  | { kind: "result"; target: string; state: VersionProbe }

type ProbeTarget =
  | { kind: "field"; origin: string }
  | { kind: "console-discovery"; origin: string }

export function createWorkshopProbe(deps: {
  consoleOrigin: string | null
  fetchImpl: WorkshopFetch
  fieldOrigin: () => string | null
  adoptOrigin: (origin: string) => void
  notify: () => void
}) {
  let probe: ProbeRun = { kind: "idle" }
  let probeGen = 0

  const abortProbe = () => {
    if (probe.kind === "checking") {
      probe.controller.abort()
    }
  }

  const finishProbe = (target: string, gen: number, state: VersionProbe) => {
    if (gen !== probeGen) {
      return
    }
    const fieldOrigin = deps.fieldOrigin()
    if (
      fieldOrigin === null &&
      state.status === "ok" &&
      target === deps.consoleOrigin
    ) {
      probe = { kind: "result", target, state }
      deps.adoptOrigin(target)
      return
    }
    if (fieldOrigin === target) {
      probe = { kind: "result", target, state }
      deps.notify()
      return
    }
    probe = { kind: "idle" }
  }

  const resolveTarget = (serviceOriginField: string): ProbeTarget | null => {
    const fieldOrigin = parseServiceOrigin(serviceOriginField)
    if (fieldOrigin !== null) {
      return { kind: "field", origin: fieldOrigin }
    }
    if (deps.consoleOrigin !== null) {
      return { kind: "console-discovery", origin: deps.consoleOrigin }
    }
    return null
  }

  const shouldSkipProbe = (target: ProbeTarget): boolean => {
    if (probe.kind === "checking" && probe.target === target.origin) {
      return true
    }
    if (probe.kind !== "result" || probe.target !== target.origin) {
      return false
    }
    return target.kind === "field" && deps.fieldOrigin() === target.origin
  }

  const startProbe = (target: ProbeTarget) => {
    if (shouldSkipProbe(target)) {
      return
    }
    probeGen += 1
    const gen = probeGen
    abortProbe()
    const controller = new AbortController()
    probe = { kind: "checking", target: target.origin, controller }
    void runVersionProbe({
      origin: target.origin,
      signal: controller.signal,
      fetchImpl: deps.fetchImpl,
    }).then((state) => {
      finishProbe(target.origin, gen, state)
    })
  }

  const ensure = (serviceOriginField: string) => {
    const target = resolveTarget(serviceOriginField)
    if (target !== null) {
      startProbe(target)
      return
    }
    probeGen += 1
    abortProbe()
    probe = { kind: "idle" }
  }

  const versionFor = (canonicalOrigin: string | null): VersionState => {
    if (canonicalOrigin === null) {
      return { status: "idle" }
    }
    if (probe.kind === "result" && probe.target === canonicalOrigin) {
      return probe.state
    }
    return { status: "checking" }
  }

  return { ensure, versionFor }
}
