import { CircleAlertIcon, CopyIcon, GlobeIcon } from "lucide-react"

import { Alert, AlertTitle } from "@/components/ui/alert.tsx"
import { Button } from "@/components/ui/button.tsx"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card.tsx"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field.tsx"
import { Textarea } from "@/components/ui/textarea.tsx"
import { t } from "@/lib/i18n.ts"
import type {
  WorkshopSessionActions,
  WorkshopSessionView,
} from "@/lib/workshop-session.ts"
import {
  clashInstallUrl,
  egernInstallUrl,
  loonInstallUrl,
  singboxInstallUrl,
  surgeInstallUrl,
} from "@/lib/workshop.ts"
import { SectionHeading } from "@/components/workshop-section.tsx"

export function WorkshopSubscription({
  view,
  actions,
  copy,
}: {
  view: WorkshopSessionView
  actions: WorkshopSessionActions
  copy: ReturnType<typeof t>
}) {
  const assembled = view.assembled
  const previewEnabled = view.previewReady
  const url = assembled.url
  const clashInstallHref =
    assembled.clashInstall && url !== null ? clashInstallUrl(url) : null
  const surgeInstallHref =
    assembled.surgeInstall && url !== null ? surgeInstallUrl(url) : null
  const loonInstallHref =
    assembled.loonInstall && url !== null ? loonInstallUrl(url) : null
  const egernInstallHref =
    assembled.egernInstall && url !== null ? egernInstallUrl(url) : null
  const singboxInstallHref =
    assembled.singboxInstall && url !== null ? singboxInstallUrl(url) : null

  return (
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
              <p className="text-sm font-medium">{copy.subscriptionTargets}</p>
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
        {loonInstallHref !== null ? (
          <Button
            nativeButton={false}
            variant="outline"
            render={<a href={loonInstallHref} />}
          >
            {copy.loonInstall}
          </Button>
        ) : null}
        {egernInstallHref !== null ? (
          <Button
            nativeButton={false}
            variant="outline"
            render={<a href={egernInstallHref} />}
          >
            {copy.egernInstall}
          </Button>
        ) : null}
        {singboxInstallHref !== null ? (
          <Button
            nativeButton={false}
            variant="outline"
            render={<a href={singboxInstallHref} />}
          >
            {copy.singboxInstall}
          </Button>
        ) : null}
      </CardFooter>
    </Card>
  )
}
