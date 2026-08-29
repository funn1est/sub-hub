import * as React from "react"
import {
  CircleAlertIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  GlobeIcon,
  Link2Icon,
  ServerIcon,
} from "lucide-react"

import { Alert, AlertTitle } from "@/components/ui/alert.tsx"
import { Badge } from "@/components/ui/badge.tsx"
import { Button } from "@/components/ui/button.tsx"
import {
  Card,
  CardAction,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card.tsx"
import {
  Field,
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
import { Textarea } from "@/components/ui/textarea.tsx"
import { t } from "@/lib/i18n.ts"
import type { Locale } from "@/lib/persist.ts"
import {
  configChoiceGroups,
  selectedConfigChoice,
} from "@/lib/workshop-config.ts"
import type {
  WorkshopSessionActions,
  WorkshopSessionView,
} from "@/lib/workshop-session.ts"
import { clashInstallUrl, surgeInstallUrl, urlField } from "@/lib/workshop.ts"
import { PreviewCard } from "@/components/workshop-preview.tsx"
import { WorkshopOptions } from "@/components/workshop-options.tsx"
import { SourceFields } from "@/components/workshop-source-fields.tsx"
import {
  SectionCard,
  SectionHeading,
  VersionAlert,
  VersionBadge,
} from "@/components/workshop-section.tsx"

type WorkshopProps = {
  view: WorkshopSessionView
  actions: WorkshopSessionActions
  locale: Locale
}

export function Workshop({ view, actions, locale }: WorkshopProps) {
  const copy = t(locale)
  const fields = view.fields
  const assembled = view.assembled
  const canCollapseService = view.serviceCollapsible
  const showCustomConfigField = view.configSelection === "custom"
  const previewEnabled = view.previewReady
  const clashInstallHref =
    assembled.clashInstall && assembled.url !== null
      ? clashInstallUrl(assembled.url)
      : null
  const surgeInstallHref =
    assembled.surgeInstall && assembled.url !== null
      ? surgeInstallUrl(assembled.url)
      : null
  const [revealToken, setRevealToken] = React.useState(false)
  const [serviceOpen, setServiceOpen] = React.useState(
    () => view.canonicalOrigin === null
  )
  const showServiceFields = serviceOpen || !canCollapseService
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
          previewEnabled
        ) {
          event.preventDefault()
          void actions.preview()
        }
      }}
    >
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
              {canCollapseService ? (
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
                      actions.patch({
                        serviceOrigin: event.target.value,
                      })
                    }
                    onBlur={() => actions.blurOrigin()}
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
                      actions.patch({
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
          <CardContent>
            <VersionAlert state={view.version} copy={copy} />
          </CardContent>
        )}
      </Card>

      <SectionCard
        icon={<Link2Icon />}
        title={copy.sources}
        description={copy.sourcesDescription}
      >
        <SourceFields
          fields={fields}
          sourceInvalid={view.sourceInvalid}
          copy={copy}
          actions={actions}
        />
      </SectionCard>

      <WorkshopOptions
        fields={fields}
        configInvalid={view.configInvalid}
        showCustomConfigField={showCustomConfigField}
        configGroups={configGroups}
        selectedConfig={selectedConfig}
        copy={copy}
        locale={locale}
        actions={actions}
      />

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
            {assembled.siblings.length > 0 ? (
              <div className="flex flex-col gap-2">
                <p className="text-sm font-medium">
                  {copy.subscriptionTargets}
                </p>
                <ul className="flex flex-col gap-px overflow-hidden rounded-lg bg-muted/60 p-1">
                  {assembled.siblings.map((sibling) => (
                    <li
                      key={sibling.target}
                      className="flex items-center gap-2 rounded-md px-2.5 py-1.5"
                    >
                      <span className="w-16 shrink-0 font-mono text-xs">
                        {sibling.target}
                      </span>
                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">
                        {sibling.url}
                      </span>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon-xs"
                        aria-label={`${copy.copyUrl} ${sibling.target}`}
                        disabled={sibling.overLimit}
                        onClick={() => void actions.copy(sibling.url)}
                      >
                        <CopyIcon />
                      </Button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </FieldGroup>
        </CardContent>
        <CardFooter>
          <Button
            type="button"
            onClick={() => void actions.copy()}
            disabled={assembled.url === null}
          >
            <CopyIcon data-icon="inline-start" />
            {copy.copyUrl}
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={() => void actions.preview()}
            disabled={!previewEnabled}
          >
            {copy.preview}
          </Button>
          {clashInstallHref !== null ? (
            <Button
              nativeButton={false}
              variant="outline"
              render={<a href={clashInstallHref} />}
            >
              {copy.clashInstall}
            </Button>
          ) : null}
          {surgeInstallHref !== null ? (
            <Button
              nativeButton={false}
              variant="outline"
              render={<a href={surgeInstallHref} />}
            >
              {copy.surgeInstall}
            </Button>
          ) : null}
        </CardFooter>
      </Card>

      <PreviewCard
        locale={locale}
        preview={view.preview}
        copy={copy}
        onDownload={actions.download}
      />

      <p className="pb-4 text-center text-xs text-muted-foreground">
        {copy.agpl}
      </p>
    </main>
  )
}
