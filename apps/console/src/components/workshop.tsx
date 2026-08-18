import * as React from "react"
import {
  CopyIcon,
  DownloadIcon,
  EyeIcon,
  EyeOffIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx"
import { Badge } from "@/components/ui/badge.tsx"
import { Button } from "@/components/ui/button.tsx"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.tsx"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.tsx"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field.tsx"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group.tsx"
import { ScrollArea } from "@/components/ui/scroll-area.tsx"
import { Spinner } from "@/components/ui/spinner.tsx"
import { Switch } from "@/components/ui/switch.tsx"
import { Textarea } from "@/components/ui/textarea.tsx"
import { toast } from "@/components/ui/toast.tsx"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group.tsx"
import { knownErrorTitle, t } from "@/lib/i18n.ts"
import type { Locale, PersistedWorkshop, Theme } from "@/lib/persist.ts"
import {
  classifyFetchFailure,
  classifyPreviewBody,
  classifyVersionBody,
  fallbackDownloadName,
  filenameFromDisposition,
  pickExposedHeaders,
  truncatePreviewBody,
  type FetchFailure,
  type PreviewBodyKind,
} from "@/lib/preview.ts"
import {
  ACL4SSR_FULL_URL,
  ACL4SSR_ONLINE_URL,
  assembleSubscription,
  clashInstallUrl,
  configPresetOf,
  MAX_SOURCES,
  parseAccessToken,
  parseHttpsResourceUrl,
  parseServiceOrigin,
  parseSubscriptionUrl,
  TARGETS,
  type Target,
} from "@/lib/workshop.ts"

type WorkshopProps = {
  state: PersistedWorkshop
  onChange: (next: PersistedWorkshop) => void
}

type VersionState =
  | { status: "idle" }
  | { status: "checking" }
  | { status: "ok"; body: string }
  | { status: "other" }
  | { status: "unreachable" }

type PreviewState =
  | { status: "idle" }
  | { status: "loading" }
  | {
      status: "done"
      httpStatus: number
      kind: PreviewBodyKind
      headers: { name: string; value: string }[]
      body: string
      viewText: string
      truncated: boolean
      filename: string
    }
  | { status: "unreachable"; cause: FetchFailure }

export function Workshop({ state, onChange }: WorkshopProps) {
  const copy = t(state.locale)
  const assembled = assembleSubscription(state)
  const originValid =
    state.serviceOrigin.trim().length === 0 ||
    parseServiceOrigin(state.serviceOrigin) !== null
  const tokenValid = parseAccessToken(state.accessToken).ok
  const configValid =
    state.configUrl.trim().length === 0 ||
    parseHttpsResourceUrl(state.configUrl) !== null
  const canonicalOrigin = parseServiceOrigin(state.serviceOrigin)
  const preset = configPresetOf(state.configUrl)

  const [revealToken, setRevealToken] = React.useState(false)
  const [pasteRaw, setPasteRaw] = React.useState("")
  const [pasteError, setPasteError] = React.useState<string | null>(null)
  const [pasteWarnings, setPasteWarnings] = React.useState<string[]>([])
  const [probe, setProbe] = React.useState<{
    origin: string
    state: Exclude<VersionState, { status: "idle" }>
  } | null>(null)
  const [preview, setPreview] = React.useState<PreviewState>({ status: "idle" })
  const version: VersionState =
    canonicalOrigin === null
      ? { status: "idle" }
      : probe === null || probe.origin !== canonicalOrigin
        ? { status: "checking" }
        : probe.state

  React.useEffect(() => {
    document.documentElement.lang = state.locale === "zh" ? "zh-CN" : "en"
    document.title = copy.title
  }, [copy.title, state.locale])

  React.useEffect(() => {
    if (canonicalOrigin === null) {
      return undefined
    }

    const origin = canonicalOrigin
    const controller = new AbortController()
    void fetch(`${origin}/version`, { signal: controller.signal })
      .then(async (response) => {
        const body = await response.text()
        if (controller.signal.aborted) {
          return
        }
        if (classifyVersionBody(body) === "sub-hub") {
          setProbe({ origin, state: { status: "ok", body: body.trim() } })
          return
        }
        setProbe({ origin, state: { status: "other" } })
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setProbe({ origin, state: { status: "unreachable" } })
        }
      })

    return () => {
      controller.abort()
    }
  }, [canonicalOrigin])

  const patch = (partial: Partial<PersistedWorkshop>) => {
    onChange({ ...state, ...partial })
  }

  const setSources = (sources: string[]) => {
    patch({ sources: sources.length > 0 ? sources : [""] })
  }

  const onImport = () => {
    const parsed = parseSubscriptionUrl(pasteRaw)
    if (!parsed.ok) {
      setPasteError(copy.importInvalid)
      setPasteWarnings([])
      return
    }
    setPasteError(null)
    setPasteWarnings(parsed.warnings.map((warning) => copy.pasteWarnings[warning]))
    onChange({
      ...state,
      serviceOrigin: parsed.workshop.serviceOrigin ?? state.serviceOrigin,
      accessToken: parsed.workshop.accessToken ?? state.accessToken,
      sources: parsed.workshop.sources ?? state.sources,
      target: parsed.workshop.target ?? state.target,
      configUrl: parsed.workshop.configUrl ?? state.configUrl,
      appendInfo: parsed.workshop.appendInfo ?? state.appendInfo,
    })
  }

  const onCopy = async () => {
    if (assembled.url === null) {
      return
    }
    try {
      await navigator.clipboard.writeText(assembled.url)
      toast.add({ type: "success", title: copy.copied })
    } catch {
      toast.add({ type: "error", title: copy.copyFailed })
    }
  }

  const onPreview = async () => {
    if (assembled.url === null || assembled.overLimit) {
      return
    }
    setPreview({ status: "loading" })
    try {
      const response = await fetch(assembled.url)
      const body = await response.text()
      const truncated = truncatePreviewBody(body)
      const kind = classifyPreviewBody(response.status, body)
      setPreview({
        status: "done",
        httpStatus: response.status,
        kind,
        headers: pickExposedHeaders(response.headers),
        body,
        viewText: truncated.text,
        truncated: truncated.truncated,
        filename:
          filenameFromDisposition(response.headers.get("content-disposition")) ??
          fallbackDownloadName(state.target),
      })
    } catch {
      setPreview({
        status: "unreachable",
        cause: classifyFetchFailure({
          pageHttps: window.location.protocol === "https:",
          serviceOrigin: canonicalOrigin ?? state.serviceOrigin,
        }),
      })
    }
  }

  const onDownload = () => {
    if (preview.status !== "done" || preview.httpStatus !== 200) {
      return
    }
    const blob = new Blob([preview.body], { type: "text/plain;charset=utf-8" })
    const objectUrl = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = objectUrl
    link.download = preview.filename
    link.click()
    URL.revokeObjectURL(objectUrl)
  }

  const previewEnabled = assembled.url !== null && !assembled.overLimit
  const showClash =
    assembled.url !== null &&
    (state.target === "clash" || state.target === "mihomo")

  return (
    <div className="mx-auto flex min-h-svh w-full max-w-3xl flex-col gap-6 p-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 flex-col gap-1">
          <h1 className="font-heading text-2xl font-medium">{copy.title}</h1>
          <p className="text-sm text-muted-foreground">{copy.tagline}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <LocaleMenu
            label={copy.language}
            locale={state.locale}
            onChange={(locale) => patch({ locale })}
          />
          <ThemeMenu
            label={copy.theme}
            theme={state.theme}
            system={copy.themeSystem}
            light={copy.themeLight}
            dark={copy.themeDark}
            onChange={(theme) => patch({ theme })}
          />
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>{copy.service}</CardTitle>
          <CardDescription>{copy.serviceDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field data-invalid={!originValid || undefined}>
              <FieldLabel htmlFor="service-origin">{copy.serviceOrigin}</FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id="service-origin"
                  value={state.serviceOrigin}
                  autoComplete="url"
                  spellCheck={false}
                  aria-invalid={!originValid || undefined}
                  placeholder="http://127.0.0.1:25500"
                  onChange={(event) => patch({ serviceOrigin: event.target.value })}
                  onBlur={() => {
                    const canonical = parseServiceOrigin(state.serviceOrigin)
                    if (canonical !== null && canonical !== state.serviceOrigin) {
                      patch({ serviceOrigin: canonical })
                    }
                  }}
                />
              </InputGroup>
              <FieldDescription>{copy.serviceOriginHint}</FieldDescription>
            </Field>
            <Field data-invalid={!tokenValid || undefined}>
              <FieldLabel htmlFor="access-token">{copy.accessToken}</FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id="access-token"
                  type={revealToken ? "text" : "password"}
                  value={state.accessToken}
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={!tokenValid || undefined}
                  onChange={(event) => patch({ accessToken: event.target.value })}
                />
                <InputGroupAddon align="inline-end">
                  <InputGroupButton
                    size="icon-xs"
                    aria-label={revealToken ? copy.hideToken : copy.showToken}
                    onClick={() => setRevealToken((current) => !current)}
                  >
                    {revealToken ? <EyeOffIcon /> : <EyeIcon />}
                  </InputGroupButton>
                </InputGroupAddon>
              </InputGroup>
              <FieldDescription>{copy.accessTokenHint}</FieldDescription>
            </Field>
            <VersionStatus state={version} copy={copy} />
          </FieldGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{copy.sources}</CardTitle>
          <CardDescription>{copy.sourcesDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            {state.sources.map((source, index) => {
              const invalid = source.includes("|")
              return (
                <Field key={index} data-invalid={invalid || undefined}>
                  <FieldLabel htmlFor={`source-${index}`}>
                    {copy.sourceN} {index + 1}
                  </FieldLabel>
                  <InputGroup>
                    <InputGroupInput
                      id={`source-${index}`}
                      value={source}
                      spellCheck={false}
                      aria-invalid={invalid || undefined}
                      onChange={(event) => {
                        const next = state.sources.slice()
                        next[index] = event.target.value
                        setSources(next)
                      }}
                    />
                    {state.sources.length > 1 ? (
                      <InputGroupAddon align="inline-end">
                        <InputGroupButton
                          size="icon-xs"
                          aria-label={copy.removeSource}
                          onClick={() => {
                            setSources(state.sources.filter((_, item) => item !== index))
                          }}
                        >
                          <Trash2Icon />
                        </InputGroupButton>
                      </InputGroupAddon>
                    ) : null}
                  </InputGroup>
                </Field>
              )
            })}
            {state.sources.length < MAX_SOURCES ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => setSources([...state.sources, ""])}
              >
                <PlusIcon data-icon="inline-start" />
                {copy.addSource}
              </Button>
            ) : null}
          </FieldGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{copy.options}</CardTitle>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field>
              <FieldLabel>{copy.target}</FieldLabel>
              <ToggleGroup
                value={[state.target]}
                onValueChange={(value) => {
                  const next = value[0]
                  if (next !== undefined) {
                    patch({ target: next as Target })
                  }
                }}
                spacing={2}
                className="flex-wrap"
              >
                {TARGETS.map((target) => (
                  <ToggleGroupItem key={target} value={target}>
                    {target}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            </Field>
            <Field>
              <FieldLabel>{copy.config}</FieldLabel>
              <ToggleGroup
                value={[preset === "custom" ? "custom" : preset]}
                onValueChange={(value) => {
                  const next = value[0]
                  if (next === "builtin") {
                    patch({ configUrl: "" })
                  } else if (next === "online") {
                    patch({ configUrl: ACL4SSR_ONLINE_URL })
                  } else if (next === "full") {
                    patch({ configUrl: ACL4SSR_FULL_URL })
                  }
                }}
                spacing={2}
                className="flex-wrap"
              >
                <ToggleGroupItem value="builtin">{copy.configBuiltin}</ToggleGroupItem>
                <ToggleGroupItem value="online">{copy.configOnline}</ToggleGroupItem>
                <ToggleGroupItem value="full">{copy.configFull}</ToggleGroupItem>
                <ToggleGroupItem value="custom">{copy.configCustom}</ToggleGroupItem>
              </ToggleGroup>
            </Field>
            <Field data-invalid={!configValid || undefined}>
              <FieldLabel htmlFor="config-url">{copy.configUrl}</FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id="config-url"
                  value={state.configUrl}
                  spellCheck={false}
                  aria-invalid={!configValid || undefined}
                  placeholder="https://"
                  onChange={(event) => patch({ configUrl: event.target.value })}
                />
              </InputGroup>
            </Field>
            <Field orientation="horizontal">
              <FieldLabel htmlFor="append-info">{copy.appendInfo}</FieldLabel>
              <Switch
                id="append-info"
                checked={state.appendInfo}
                onCheckedChange={(checked) => patch({ appendInfo: checked })}
              />
              <FieldDescription>{copy.appendInfoHint}</FieldDescription>
            </Field>
          </FieldGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{copy.subscription}</CardTitle>
          <CardDescription>{copy.subscriptionDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="subscription-url">{copy.subscription}</FieldLabel>
              <Textarea
                id="subscription-url"
                readOnly
                value={assembled.url ?? ""}
                rows={3}
                className="font-mono text-xs"
              />
            </Field>
            {assembled.overLimit ? (
              <Alert variant="destructive">
                <AlertTitle>{copy.overLimit}</AlertTitle>
              </Alert>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                onClick={() => void onCopy()}
                disabled={assembled.url === null}
              >
                <CopyIcon data-icon="inline-start" />
                {copy.copyUrl}
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => void onPreview()}
                disabled={!previewEnabled || preview.status === "loading"}
              >
                {preview.status === "loading" ? (
                  <Spinner data-icon="inline-start" />
                ) : null}
                {preview.status === "loading" ? copy.previewing : copy.preview}
              </Button>
              {showClash && assembled.url !== null ? (
                <Button
                  nativeButton={false}
                  variant="outline"
                  render={<a href={clashInstallUrl(assembled.url)} />}
                >
                  {copy.clashInstall}
                </Button>
              ) : null}
            </div>
            <Field data-invalid={pasteError !== null || undefined}>
              <FieldLabel htmlFor="paste-url">{copy.pasteUrl}</FieldLabel>
              <Textarea
                id="paste-url"
                value={pasteRaw}
                spellCheck={false}
                aria-invalid={pasteError !== null || undefined}
                rows={3}
                className="font-mono text-xs"
                onChange={(event) => {
                  setPasteRaw(event.target.value)
                  setPasteError(null)
                }}
              />
              <FieldDescription>{copy.pasteUrlHint}</FieldDescription>
              {pasteError !== null ? <FieldError>{pasteError}</FieldError> : null}
            </Field>
            <Button type="button" variant="outline" onClick={onImport}>
              {copy.import}
            </Button>
            {pasteWarnings.map((warning) => (
              <Alert key={warning}>
                <AlertDescription>{warning}</AlertDescription>
              </Alert>
            ))}
          </FieldGroup>
        </CardContent>
      </Card>

      <PreviewCard
        locale={state.locale}
        preview={preview}
        copy={copy}
        onDownload={onDownload}
      />

      <p className="pb-6 text-xs text-muted-foreground">{copy.agpl}</p>
    </div>
  )
}

function VersionStatus({
  state,
  copy,
}: {
  state: VersionState
  copy: ReturnType<typeof t>
}) {
  if (state.status === "idle") {
    return null
  }
  if (state.status === "checking") {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Spinner />
        {copy.versionChecking}
      </div>
    )
  }
  if (state.status === "ok") {
    return <Badge variant="secondary">{state.body}</Badge>
  }
  if (state.status === "other") {
    return (
      <Alert>
        <AlertTitle>{copy.versionOther}</AlertTitle>
      </Alert>
    )
  }
  return (
    <Alert>
      <AlertTitle>{copy.versionUnreachable}</AlertTitle>
    </Alert>
  )
}

function PreviewCard({
  locale,
  preview,
  copy,
  onDownload,
}: {
  locale: Locale
  preview: PreviewState
  copy: ReturnType<typeof t>
  onDownload: () => void
}) {
  if (preview.status === "idle" || preview.status === "loading") {
    return null
  }

  if (preview.status === "unreachable") {
    const title =
      preview.cause === "mixed-content"
        ? copy.unreachableMixed
        : preview.cause === "local-network"
          ? copy.unreachableLna
          : copy.unreachableCors
    return (
      <Card>
        <CardHeader>
          <CardTitle>{copy.preview}</CardTitle>
        </CardHeader>
        <CardContent>
          <Alert>
            <AlertTitle>{title}</AlertTitle>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  const errorTitle =
    preview.kind.kind === "known-error"
      ? knownErrorTitle(locale, preview.kind.body)
      : `${copy.status} ${preview.httpStatus}`

  return (
    <Card>
      <CardHeader>
        <CardTitle>{copy.preview}</CardTitle>
        <CardDescription>{errorTitle}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4">
          {preview.kind.kind === "known-error" ? (
            <Alert variant="destructive">
              <AlertTitle>{errorTitle}</AlertTitle>
              <AlertDescription className="font-mono">
                {preview.kind.body}
              </AlertDescription>
            </Alert>
          ) : null}
          <Alert>
            <AlertTitle>{copy.secretWarning}</AlertTitle>
          </Alert>
          {preview.headers.length > 0 ? (
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium">{copy.headers}</p>
              <ul className="flex flex-col gap-1 font-mono text-xs">
                {preview.headers.map((header) => (
                  <li key={header.name}>
                    {header.name}: {header.value}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">{copy.body}</p>
            {preview.truncated ? (
              <p className="text-sm text-muted-foreground">{copy.truncated}</p>
            ) : null}
            <ScrollArea className="h-80 rounded-lg border">
              <pre className="whitespace-pre-wrap break-all p-3 font-mono text-xs">
                {preview.viewText}
              </pre>
            </ScrollArea>
          </div>
          {preview.httpStatus === 200 ? (
            <Button type="button" variant="outline" onClick={onDownload}>
              <DownloadIcon data-icon="inline-start" />
              {copy.download}
            </Button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  )
}

function LocaleMenu({
  label,
  locale,
  onChange,
}: {
  label: string
  locale: Locale
  onChange: (locale: Locale) => void
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
        {label}: {locale === "zh" ? "中文" : "English"}
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuGroup>
          <DropdownMenuItem onClick={() => onChange("zh")}>中文</DropdownMenuItem>
          <DropdownMenuItem onClick={() => onChange("en")}>English</DropdownMenuItem>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ThemeMenu({
  label,
  theme,
  system,
  light,
  dark,
  onChange,
}: {
  label: string
  theme: Theme
  system: string
  light: string
  dark: string
  onChange: (theme: Theme) => void
}) {
  const current = theme === "system" ? system : theme === "light" ? light : dark
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
        {label}: {current}
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuGroup>
          <DropdownMenuItem onClick={() => onChange("system")}>{system}</DropdownMenuItem>
          <DropdownMenuItem onClick={() => onChange("light")}>{light}</DropdownMenuItem>
          <DropdownMenuItem onClick={() => onChange("dark")}>{dark}</DropdownMenuItem>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
