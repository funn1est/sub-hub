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
  PlusIcon,
  ServerIcon,
  Settings2Icon,
  ShieldAlertIcon,
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
  ComboboxTrigger,
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
  Field,
  FieldContent,
  FieldDescription,
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
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group.tsx"
import {
  knownErrorTitle,
  skippedSummary,
  t,
  type Messages,
} from "@/lib/i18n.ts"
import type { Locale } from "@/lib/persist.ts"
import {
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  acl4ssrConfigLabel,
  type Acl4ssrConfigFile,
} from "@/lib/acl4ssr-catalog.ts"
import { TARGETS, isTarget } from "@/lib/service-contract.ts"
import type {
  ConfigSelectionId,
  VersionState,
  WorkshopSession,
} from "@/lib/workshop-session.ts"
import type { PreviewState } from "@/lib/workshop.ts"

type ConfigChoice = {
  id: "none" | "custom" | Acl4ssrConfigFile
  label: string
}

type ConfigChoiceGroup = {
  value: string
  items: ConfigChoice[]
}

const urlField = {
  inputMode: "url" as const,
  autoCapitalize: "none" as const,
  autoCorrect: "off" as const,
  spellCheck: false,
}

type WorkshopProps = {
  session: WorkshopSession
  locale: Locale
  banner?: React.ReactNode
}

export function Workshop({ session, locale, banner }: WorkshopProps) {
  const view = React.useSyncExternalStore(
    session.subscribe,
    session.getView,
    session.getView
  )
  const copy = t(locale)
  const fields = view.fields
  const assembled = view.assembled
  const [revealToken, setRevealToken] = React.useState(false)
  const [serviceOpen, setServiceOpen] = React.useState(
    () => session.getView().canonicalOrigin === null
  )
  const showServiceFields = serviceOpen || !view.canCollapseService
  const configGroups = React.useMemo(() => configChoiceGroups(copy), [copy])
  const selectedConfig = selectedConfigChoice(
    configGroups,
    view.configSelection
  )

  return (
    <main
      className="mx-auto flex w-full max-w-3xl min-w-0 flex-col gap-5 px-4 py-6 pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:px-6"
      onKeyDown={(event) => {
        if (
          (event.metaKey || event.ctrlKey) &&
          event.key === "Enter" &&
          view.previewEnabled
        ) {
          event.preventDefault()
          void session.actions.preview()
        }
      }}
    >
      {banner}

      <Card>
        <CardHeader className="border-b">
          <SectionHeading
            icon={<ServerIcon />}
            title={copy.service}
            description={
              showServiceFields
                ? copy.serviceDescription
                : (view.canonicalOrigin ?? undefined)
            }
            descriptionClassName={showServiceFields ? undefined : "break-all"}
          />
          <CardAction>
            <div className="flex max-w-full flex-wrap items-center gap-2">
              {fields.accessToken.trim().length > 0 ? (
                <Badge variant="outline">{copy.tokenSet}</Badge>
              ) : null}
              <VersionBadge state={view.version} copy={copy} />
              {view.canCollapseService ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  aria-expanded={showServiceFields}
                  onClick={() => setServiceOpen((open) => !open)}
                >
                  {showServiceFields ? copy.done : copy.edit}
                </Button>
              ) : null}
            </div>
          </CardAction>
        </CardHeader>
        {showServiceFields ? (
          <CardContent>
            <FieldGroup>
              <Field data-invalid={view.originInvalid || undefined}>
                <FieldLabel htmlFor="service-origin">
                  {copy.serviceOrigin}
                </FieldLabel>
                <InputGroup>
                  <InputGroupInput
                    id="service-origin"
                    value={fields.serviceOrigin}
                    autoComplete="url"
                    enterKeyHint="next"
                    aria-invalid={view.originInvalid || undefined}
                    placeholder="http://127.0.0.1:25500"
                    {...urlField}
                    onChange={(event) =>
                      session.actions.patch({
                        serviceOrigin: event.target.value,
                      })
                    }
                    onBlur={() => session.actions.blurOrigin()}
                  />
                </InputGroup>
                <FieldDescription>{copy.serviceOriginHint}</FieldDescription>
              </Field>
              <Field data-invalid={view.tokenInvalid || undefined}>
                <FieldLabel htmlFor="access-token">
                  {copy.accessToken}
                </FieldLabel>
                <InputGroup>
                  <InputGroupInput
                    id="access-token"
                    type={revealToken ? "text" : "password"}
                    value={fields.accessToken}
                    autoComplete="off"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    enterKeyHint="next"
                    aria-invalid={view.tokenInvalid || undefined}
                    onChange={(event) =>
                      session.actions.patch({
                        accessToken: event.target.value,
                      })
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
              <VersionAlert state={view.version} copy={copy} />
            </FieldGroup>
          </CardContent>
        ) : (
          <VersionAlert state={view.version} copy={copy} padded />
        )}
      </Card>

      <SectionCard
        icon={<Link2Icon />}
        title={copy.sources}
        description={copy.sourcesDescription}
      >
        <FieldGroup>
          {fields.sources.map((source, index) => {
            const invalid = view.sourceInvalid[index] === true
            return (
              <Field key={index} data-invalid={invalid || undefined}>
                <FieldLabel htmlFor={`source-${index}`} className="sr-only">
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
                    enterKeyHint="next"
                    aria-invalid={invalid || undefined}
                    {...urlField}
                    onChange={(event) => {
                      const next = fields.sources.slice()
                      next[index] = event.target.value
                      session.actions.patch({ sources: next })
                    }}
                    onPaste={(event) => {
                      const field = event.currentTarget
                      const outcome = session.actions.pasteIntoSource(
                        event.clipboardData.getData("text"),
                        {
                          value: field.value,
                          selectionStart: field.selectionStart,
                          selectionEnd: field.selectionEnd,
                        }
                      )
                      if (outcome === "imported") {
                        event.preventDefault()
                      }
                    }}
                  />
                  {fields.sources.length > 1 ? (
                    <InputGroupAddon align="inline-end">
                      <InputGroupButton
                        size="icon-xs"
                        aria-label={copy.removeSource}
                        onClick={() => {
                          session.actions.patch({
                            sources: fields.sources.filter(
                              (_, item) => item !== index
                            ),
                          })
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
          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={() =>
              session.actions.patch({ sources: [...fields.sources, ""] })
            }
          >
            <PlusIcon data-icon="inline-start" />
            {copy.addSource}
          </Button>
          {view.pasteWarnings.map((warning) => (
            <Alert key={warning}>
              <CircleAlertIcon />
              <AlertDescription>{copy.pasteWarnings[warning]}</AlertDescription>
            </Alert>
          ))}
        </FieldGroup>
      </SectionCard>

      <SectionCard icon={<Settings2Icon />} title={copy.options}>
        <FieldGroup>
          <Field>
            <FieldLabel>{copy.target}</FieldLabel>
            <ToggleGroup
              variant="outline"
              size="sm"
              value={[fields.target]}
              onValueChange={(value) => {
                const next = value[0]
                if (next !== undefined && isTarget(next)) {
                  session.actions.patch({ target: next })
                }
              }}
              spacing={2}
              className="w-full max-w-full flex-wrap"
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
                session.actions.selectConfig(item.id)
              }}
              itemToStringValue={(item) => item.label}
            >
              <ComboboxTrigger
                id="config-preset"
                render={
                  <Button
                    variant="outline"
                    className="w-full min-w-0 justify-between font-normal"
                  />
                }
              >
                <span className="min-w-0 truncate">{selectedConfig.label}</span>
              </ComboboxTrigger>
              <ComboboxContent>
                <ComboboxInput
                  placeholder={copy.configSearch}
                  showTrigger={false}
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  enterKeyHint="search"
                />
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
          {view.showCustomConfigField ? (
            <Field data-invalid={view.configInvalid || undefined}>
              <FieldLabel htmlFor="config-url">{copy.configUrl}</FieldLabel>
              <InputGroup>
                <InputGroupInput
                  id="config-url"
                  value={fields.configUrl}
                  enterKeyHint="done"
                  aria-invalid={view.configInvalid || undefined}
                  placeholder="https://"
                  {...urlField}
                  onChange={(event) =>
                    session.actions.editCustomConfigUrl(event.target.value)
                  }
                />
              </InputGroup>
            </Field>
          ) : null}
          <Field orientation="horizontal">
            <FieldContent>
              <FieldLabel htmlFor="append-info">{copy.appendInfo}</FieldLabel>
              <FieldDescription>{copy.appendInfoHint}</FieldDescription>
            </FieldContent>
            <Switch
              id="append-info"
              checked={fields.appendInfo}
              onCheckedChange={(checked) =>
                session.actions.patch({ appendInfo: checked })
              }
            />
          </Field>
        </FieldGroup>
      </SectionCard>

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
                rows={3}
                placeholder={copy.previewBlocked}
                className="font-mono text-base break-all md:text-sm"
                onFocus={(event) => event.currentTarget.select()}
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
        <CardFooter>
          <Button
            type="button"
            onClick={() => void session.actions.copy()}
            disabled={assembled.url === null}
          >
            <CopyIcon data-icon="inline-start" />
            {copy.copyUrl}
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={() => void session.actions.preview()}
            disabled={!view.previewEnabled}
          >
            {view.preview.status === "loading" ? (
              <Spinner data-icon="inline-start" />
            ) : null}
            {view.preview.status === "loading" ? copy.previewing : copy.preview}
          </Button>
          {view.clashInstallHref !== null ? (
            <Button
              nativeButton={false}
              variant="outline"
              render={<a href={view.clashInstallHref} />}
            >
              {copy.clashInstall}
            </Button>
          ) : null}
        </CardFooter>
      </Card>

      <PreviewCard
        locale={locale}
        preview={view.preview}
        copy={copy}
        onDownload={session.actions.download}
      />

      <p className="pb-4 text-center text-xs text-muted-foreground">
        {copy.agpl}
      </p>
    </main>
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

function SectionHeading({
  icon,
  title,
  description,
  descriptionClassName,
}: {
  icon: React.ReactNode
  title: string
  description?: string
  descriptionClassName?: string
}) {
  return (
    <div className="flex items-start gap-3">
      <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground [&_svg]:size-4">
        {icon}
      </span>
      <div className="flex min-w-0 flex-col gap-1">
        <CardTitle>{title}</CardTitle>
        {description ? (
          <CardDescription className={descriptionClassName}>
            {description}
          </CardDescription>
        ) : null}
      </div>
    </div>
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
    return (
      <Badge variant="secondary" className="max-w-full truncate">
        {state.body}
      </Badge>
    )
  }
  return <Badge variant="destructive">{copy.versionIssue}</Badge>
}

function VersionAlert({
  state,
  copy,
  padded = false,
}: {
  state: VersionState
  copy: ReturnType<typeof t>
  padded?: boolean
}) {
  let alert: React.ReactNode = null
  if (state.status === "other") {
    alert = (
      <Alert>
        <CircleAlertIcon />
        <AlertTitle>{copy.versionOther}</AlertTitle>
      </Alert>
    )
  } else if (state.status === "unreachable") {
    alert = (
      <Alert>
        <CircleAlertIcon />
        <AlertTitle>{copy.versionUnreachable}</AlertTitle>
      </Alert>
    )
  }
  if (alert === null) {
    return null
  }
  if (padded) {
    return <CardContent>{alert}</CardContent>
  }
  return alert
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
      <Card>
        <CardHeader className="border-b">
          <SectionHeading icon={<FileCode2Icon />} title={copy.preview} />
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Spinner />
            {copy.previewing}
          </div>
        </CardContent>
      </Card>
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
      <Card>
        <CardHeader className="border-b">
          <SectionHeading icon={<FileCode2Icon />} title={copy.preview} />
        </CardHeader>
        <CardContent>
          <Alert>
            <CircleAlertIcon />
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
            <ScrollArea className="h-[min(20rem,50svh)] rounded-lg border bg-muted/30">
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
  id: ConfigSelectionId
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
