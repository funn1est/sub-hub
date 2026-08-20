import * as React from "react"
import {
  CircleAlertIcon,
  CopyIcon,
  DownloadIcon,
  EyeIcon,
  EyeOffIcon,
  FileCode2Icon,
  GlobeIcon,
  Link2Icon,
  MonitorIcon,
  MoonIcon,
  PlusIcon,
  ServerIcon,
  Settings2Icon,
  ShieldAlertIcon,
  SunIcon,
  Trash2Icon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx"
import { Badge } from "@/components/ui/badge.tsx"
import { Button } from "@/components/ui/button.tsx"
import {
  Combobox,
  ComboboxCollection,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxGroup,
  ComboboxInput,
  ComboboxItem,
  ComboboxLabel,
  ComboboxList,
  ComboboxSeparator,
} from "@/components/ui/combobox.tsx"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.tsx"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.tsx"
import {
  Field,
  FieldContent,
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
import {
  knownErrorTitle,
  skippedSummary,
  t,
  type Messages,
} from "@/lib/i18n.ts"
import type { Locale, PersistedWorkshop, Theme } from "@/lib/persist.ts"
import {
  runPreview,
  runVersionProbe,
  type PreviewState,
} from "@/lib/preview.ts"
import {
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  MAX_SOURCES,
  TARGETS,
  accessTokenFieldValid,
  acl4ssrConfigLabel,
  acl4ssrConfigUrl,
  applyPaste,
  assembleSubscription,
  canPreview,
  clashInstallUrl,
  configFieldValid,
  configPresetOf,
  configSelectionId,
  isTarget,
  originFieldValid,
  parseServiceOrigin,
  parseSubscriptionUrl,
  showsClashInstall,
  sourceFieldInvalid,
  type Acl4ssrConfigFile,
} from "@/lib/workshop.ts"

type ConfigChoice = {
  id: "none" | "custom" | Acl4ssrConfigFile
  label: string
}

type ConfigChoiceGroup = {
  value: string
  items: ConfigChoice[]
}

type WorkshopProps = {
  state: PersistedWorkshop
  onChange: (next: PersistedWorkshop) => void
  banner?: React.ReactNode
}

type VersionState =
  | { status: "idle" }
  | { status: "checking" }
  | { status: "ok"; body: string }
  | { status: "other" }
  | { status: "unreachable" }

export function Workshop({ state, onChange, banner }: WorkshopProps) {
  const copy = t(state.locale)
  const assembled = assembleSubscription(state)
  const originValid = originFieldValid(state.serviceOrigin)
  const tokenValid = accessTokenFieldValid(state.accessToken)
  const configValid = configFieldValid(state.configUrl)
  const canonicalOrigin = parseServiceOrigin(state.serviceOrigin)
  const preset = configPresetOf(state.configUrl)
  const [revealToken, setRevealToken] = React.useState(false)
  const [pickingCustom, setPickingCustom] = React.useState(false)
  const configGroups = React.useMemo(() => configChoiceGroups(copy), [copy])
  const selectedConfig = selectedConfigChoice(
    configGroups,
    configSelectionId(preset, pickingCustom)
  )
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
    void runVersionProbe({ origin, signal: controller.signal }).then(
      (state) => {
        if (!controller.signal.aborted) {
          setProbe({ origin, state })
        }
      }
    )

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
    setPickingCustom(false)
    setPasteWarnings(
      parsed.warnings.map((warning) => copy.pasteWarnings[warning])
    )
    onChange(applyPaste(state, parsed))
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
    if (!canPreview(assembled)) {
      return
    }
    setPreview({ status: "loading" })
    setPreview(
      await runPreview({
        assembled,
        target: state.target,
        pageHttps: window.location.protocol === "https:",
      })
    )
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

  const previewEnabled = canPreview(assembled)
  const showClash = showsClashInstall(assembled, state.target)

  return (
    <div className="console-shell relative isolate">
      <div className="console-shell-bg" aria-hidden />
      <header className="sticky top-0 z-10 border-b bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between gap-3 px-6 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <img
              src="/icon.svg"
              alt=""
              className="size-9 rounded-[10px] ring-1 ring-foreground/10"
            />
            <div className="min-w-0">
              <h1 className="truncate font-heading text-base font-medium tracking-tight">
                {copy.title}
              </h1>
              <p className="hidden truncate text-xs text-muted-foreground sm:block">
                {copy.tagline}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
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
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-6 py-8">
        {banner}

        <SectionCard
          icon={<ServerIcon />}
          title={copy.service}
          description={copy.serviceDescription}
          action={<VersionBadge state={version} copy={copy} />}
        >
          <FieldGroup>
            <Field data-invalid={!originValid || undefined}>
              <FieldLabel htmlFor="service-origin">
                {copy.serviceOrigin}
              </FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id="service-origin"
                  value={state.serviceOrigin}
                  autoComplete="url"
                  spellCheck={false}
                  aria-invalid={!originValid || undefined}
                  placeholder="http://127.0.0.1:25500"
                  onChange={(event) =>
                    patch({ serviceOrigin: event.target.value })
                  }
                  onBlur={() => {
                    const canonical = parseServiceOrigin(state.serviceOrigin)
                    if (
                      canonical !== null &&
                      canonical !== state.serviceOrigin
                    ) {
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
                  onChange={(event) =>
                    patch({ accessToken: event.target.value })
                  }
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
            <VersionAlert state={version} copy={copy} />
          </FieldGroup>
        </SectionCard>

        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(20rem,0.85fr)]">
          <div className="flex flex-col gap-6">
            <SectionCard
              icon={<Link2Icon />}
              title={copy.sources}
              description={copy.sourcesDescription}
            >
              <FieldGroup>
                {state.sources.map((source, index) => {
                  const invalid = sourceFieldInvalid(source)
                  return (
                    <Field key={index} data-invalid={invalid || undefined}>
                      <FieldLabel
                        htmlFor={`source-${index}`}
                        className="sr-only"
                      >
                        {copy.sourceN} {index + 1}
                      </FieldLabel>
                      <InputGroup>
                        <InputGroupAddon align="inline-start">
                          <span className="w-4 text-center text-xs text-muted-foreground tabular-nums">
                            {index + 1}
                          </span>
                        </InputGroupAddon>
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
                                setSources(
                                  state.sources.filter(
                                    (_, item) => item !== index
                                  )
                                )
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
                    className="w-full"
                    onClick={() => setSources([...state.sources, ""])}
                  >
                    <PlusIcon data-icon="inline-start" />
                    {copy.addSource}
                  </Button>
                ) : null}
              </FieldGroup>
            </SectionCard>

            <SectionCard icon={<Settings2Icon />} title={copy.options}>
              <FieldGroup>
                <Field>
                  <FieldLabel>{copy.target}</FieldLabel>
                  <ToggleGroup
                    variant="outline"
                    size="sm"
                    value={[state.target]}
                    onValueChange={(value) => {
                      const next = value[0]
                      if (next !== undefined && isTarget(next)) {
                        patch({ target: next })
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
                  <FieldLabel htmlFor="config-preset">{copy.config}</FieldLabel>
                  <Combobox
                    items={configGroups}
                    value={selectedConfig}
                    onValueChange={(item) => {
                      if (item == null || !("id" in item)) {
                        return
                      }
                      if (item.id === "none") {
                        setPickingCustom(false)
                        patch({ configUrl: "" })
                        return
                      }
                      if (item.id === "custom") {
                        setPickingCustom(true)
                        return
                      }
                      setPickingCustom(false)
                      patch({ configUrl: acl4ssrConfigUrl(item.id) })
                    }}
                    itemToStringValue={(item) => item.label}
                  >
                    <ComboboxInput
                      id="config-preset"
                      className="w-full"
                      autoComplete="off"
                      spellCheck={false}
                    />
                    <ComboboxContent>
                      <ComboboxEmpty>{copy.configEmpty}</ComboboxEmpty>
                      <ComboboxList>
                        {(group: ConfigChoiceGroup, index: number) => (
                          <ComboboxGroup key={group.value} items={group.items}>
                            <ComboboxLabel>{group.value}</ComboboxLabel>
                            <ComboboxCollection>
                              {(item: ConfigChoice) => (
                                <ComboboxItem key={item.id} value={item}>
                                  {item.label}
                                </ComboboxItem>
                              )}
                            </ComboboxCollection>
                            {index < configGroups.length - 1 ? (
                              <ComboboxSeparator />
                            ) : null}
                          </ComboboxGroup>
                        )}
                      </ComboboxList>
                    </ComboboxContent>
                  </Combobox>
                  <FieldDescription>{copy.configHint}</FieldDescription>
                </Field>
                {pickingCustom || preset.kind === "custom" ? (
                  <Field data-invalid={!configValid || undefined}>
                    <FieldLabel htmlFor="config-url">
                      {copy.configUrl}
                    </FieldLabel>
                    <InputGroup>
                      <InputGroupInput
                        id="config-url"
                        value={state.configUrl}
                        spellCheck={false}
                        aria-invalid={!configValid || undefined}
                        placeholder="https://"
                        onChange={(event) => {
                          const next = event.target.value
                          const nextPreset = configPresetOf(next)
                          setPickingCustom(nextPreset.kind === "custom")
                          patch({ configUrl: next })
                        }}
                      />
                    </InputGroup>
                  </Field>
                ) : null}
                <Field orientation="horizontal">
                  <FieldContent>
                    <FieldLabel htmlFor="append-info">
                      {copy.appendInfo}
                    </FieldLabel>
                    <FieldDescription>{copy.appendInfoHint}</FieldDescription>
                  </FieldContent>
                  <Switch
                    id="append-info"
                    checked={state.appendInfo}
                    onCheckedChange={(checked) =>
                      patch({ appendInfo: checked })
                    }
                  />
                </Field>
              </FieldGroup>
            </SectionCard>
          </div>

          <div className="flex flex-col gap-6 lg:sticky lg:top-24 lg:self-start">
            <Card>
              <CardHeader className="border-b">
                <SectionHeading
                  icon={<GlobeIcon />}
                  title={copy.subscription}
                  description={copy.subscriptionDescription}
                />
              </CardHeader>
              <CardContent>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="subscription-url" className="sr-only">
                      {copy.subscription}
                    </FieldLabel>
                    <Textarea
                      id="subscription-url"
                      readOnly
                      value={assembled.url ?? ""}
                      rows={4}
                      placeholder={copy.previewBlocked}
                      className="font-mono text-xs"
                    />
                  </Field>
                  {assembled.overLimit ? (
                    <Alert variant="destructive">
                      <CircleAlertIcon />
                      <AlertTitle>{copy.overLimit}</AlertTitle>
                    </Alert>
                  ) : null}
                </FieldGroup>
              </CardContent>
              <CardFooter className="flex-wrap gap-2">
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
                  {preview.status === "loading"
                    ? copy.previewing
                    : copy.preview}
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
              </CardFooter>
            </Card>

            <SectionCard icon={<FileCode2Icon />} title={copy.pasteUrl}>
              <FieldGroup>
                <Field data-invalid={pasteError !== null || undefined}>
                  <FieldLabel htmlFor="paste-url" className="sr-only">
                    {copy.pasteUrl}
                  </FieldLabel>
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
                  {pasteError !== null ? (
                    <FieldError>{pasteError}</FieldError>
                  ) : null}
                </Field>
                <Button type="button" variant="outline" onClick={onImport}>
                  {copy.import}
                </Button>
                {pasteWarnings.map((warning) => (
                  <Alert key={warning}>
                    <CircleAlertIcon />
                    <AlertDescription>{warning}</AlertDescription>
                  </Alert>
                ))}
              </FieldGroup>
            </SectionCard>
          </div>
        </div>

        <PreviewCard
          locale={state.locale}
          preview={preview}
          copy={copy}
          onDownload={onDownload}
        />

        <p className="pb-4 text-center text-xs text-muted-foreground">
          {copy.agpl}
        </p>
      </main>
    </div>
  )
}

function SectionHeading({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode
  title: string
  description?: string
}) {
  return (
    <div className="flex items-start gap-3">
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground [&_svg]:size-4">
        {icon}
      </span>
      <div className="flex min-w-0 flex-col gap-1">
        <CardTitle>{title}</CardTitle>
        {description ? <CardDescription>{description}</CardDescription> : null}
      </div>
    </div>
  )
}

function SectionCard({
  icon,
  title,
  description,
  action,
  children,
}: {
  icon: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <Card>
      <CardHeader className="border-b">
        <SectionHeading icon={icon} title={title} description={description} />
        {action ? <CardAction>{action}</CardAction> : null}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function VersionBadge({
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
      <Badge variant="outline">
        <Spinner />
        <span className="sr-only">{copy.versionChecking}</span>
      </Badge>
    )
  }
  if (state.status === "ok") {
    return <Badge variant="secondary">{state.body}</Badge>
  }
  return <Badge variant="destructive">{copy.versionIssue}</Badge>
}

function VersionAlert({
  state,
  copy,
}: {
  state: VersionState
  copy: ReturnType<typeof t>
}) {
  if (state.status === "other") {
    return (
      <Alert>
        <CircleAlertIcon />
        <AlertTitle>{copy.versionOther}</AlertTitle>
      </Alert>
    )
  }
  if (state.status === "unreachable") {
    return (
      <Alert>
        <CircleAlertIcon />
        <AlertTitle>{copy.versionUnreachable}</AlertTitle>
      </Alert>
    )
  }
  return null
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
  if (preview.status === "idle") {
    return null
  }

  if (preview.status === "loading") {
    return (
      <SectionCard icon={<FileCode2Icon />} title={copy.preview}>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Spinner />
          {copy.previewing}
        </div>
      </SectionCard>
    )
  }

  if (preview.status === "unreachable") {
    const title =
      preview.cause === "mixed-content"
        ? copy.unreachableMixed
        : preview.cause === "local-network"
          ? copy.unreachableLna
          : copy.unreachableCors
    return (
      <SectionCard icon={<FileCode2Icon />} title={copy.preview}>
        <Alert>
          <CircleAlertIcon />
          <AlertTitle>{title}</AlertTitle>
        </Alert>
      </SectionCard>
    )
  }

  const errorTitle =
    preview.kind.kind === "known-error"
      ? knownErrorTitle(locale, preview.kind.body)
      : `${copy.status} ${preview.httpStatus}`
  const skipped = preview.skipped

  return (
    <Card>
      <CardHeader className="border-b">
        <SectionHeading
          icon={<FileCode2Icon />}
          title={copy.preview}
          description={errorTitle}
        />
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4">
          {preview.kind.kind === "known-error" ? (
            <Alert variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>{errorTitle}</AlertTitle>
              <AlertDescription className="font-mono">
                {preview.kind.body}
              </AlertDescription>
            </Alert>
          ) : null}
          {skipped !== null ? (
            <Alert>
              <CircleAlertIcon />
              <AlertTitle>{copy.skipped}</AlertTitle>
              <AlertDescription>
                {skippedSummary(locale, skipped)}
              </AlertDescription>
            </Alert>
          ) : null}
          <Alert>
            <ShieldAlertIcon />
            <AlertTitle>{copy.secretWarning}</AlertTitle>
          </Alert>
          {preview.headers.length > 0 ? (
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">{copy.headers}</p>
              <ul className="flex flex-col gap-px overflow-hidden rounded-lg bg-muted/60 p-1">
                {preview.headers.map((header) => (
                  <li
                    key={header.name}
                    className="flex flex-wrap gap-x-3 gap-y-1 rounded-md px-2.5 py-1.5 font-mono text-xs"
                  >
                    <span className="text-muted-foreground">{header.name}</span>
                    <span className="min-w-0 break-all">{header.value}</span>
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
            <ScrollArea className="h-80 rounded-lg border bg-muted/30">
              <pre className="p-3 font-mono text-xs break-all whitespace-pre-wrap">
                {preview.viewText}
              </pre>
            </ScrollArea>
          </div>
        </div>
      </CardContent>
      {preview.httpStatus === 200 ? (
        <CardFooter>
          <Button type="button" variant="outline" onClick={onDownload}>
            <DownloadIcon data-icon="inline-start" />
            {copy.download}
          </Button>
        </CardFooter>
      ) : null}
    </Card>
  )
}

function configChoiceGroups(copy: Messages): ConfigChoiceGroup[] {
  return [
    {
      value: copy.configNone,
      items: [{ id: "none", label: copy.configNone }],
    },
    {
      value: copy.configOnline,
      items: ACL4SSR_ONLINE_FILES.map((file) => ({
        id: file,
        label: acl4ssrConfigLabel(file),
      })),
    },
    {
      value: copy.configMini,
      items: ACL4SSR_MINI_FILES.map((file) => ({
        id: file,
        label: acl4ssrConfigLabel(file),
      })),
    },
    {
      value: copy.configFull,
      items: ACL4SSR_FULL_FILES.map((file) => ({
        id: file,
        label: acl4ssrConfigLabel(file),
      })),
    },
    {
      value: copy.configCustom,
      items: [{ id: "custom", label: copy.configCustom }],
    },
  ]
}

function selectedConfigChoice(
  groups: readonly ConfigChoiceGroup[],
  id: ReturnType<typeof configSelectionId>
): ConfigChoice {
  for (const group of groups) {
    const found = group.items.find((item) => item.id === id)
    if (found !== undefined) {
      return found
    }
  }
  const fallback = groups[0]?.items[0]
  return fallback ?? { id: "none", label: "" }
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
        {locale === "zh" ? "中文" : "EN"}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={locale}
            onValueChange={(value) => {
              if (value === "zh" || value === "en") {
                onChange(value)
              }
            }}
          >
            <DropdownMenuRadioItem value="zh">中文</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="en">English</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
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
  const Icon =
    theme === "light" ? SunIcon : theme === "dark" ? MoonIcon : MonitorIcon
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="outline" size="icon-sm" />}>
        <Icon />
        <span className="sr-only">{label}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={theme}
            onValueChange={(value) => {
              if (value === "system" || value === "light" || value === "dark") {
                onChange(value)
              }
            }}
          >
            <DropdownMenuRadioItem value="system">
              {system}
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="light">{light}</DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="dark">{dark}</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
