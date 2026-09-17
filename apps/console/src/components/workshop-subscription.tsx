import { CircleAlertIcon, CopyIcon, GlobeIcon } from 'lucide-react';

import { Alert, AlertTitle } from '@/components/ui/alert.tsx';
import { Button } from '@/components/ui/button.tsx';
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card.tsx';
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field.tsx';
import { Textarea } from '@/components/ui/textarea.tsx';
import { t } from '@/lib/i18n.ts';
import type { WorkshopSessionActions, WorkshopSessionView } from '@/lib/workshop-session.ts';
import {
  clashInstallUrl,
  egernInstallUrl,
  loonInstallUrl,
  singboxInstallUrl,
  surgeInstallUrl,
} from '@/lib/workshop.ts';
import { SectionHeading } from '@/components/workshop-section.tsx';

function installLink(
  enabled: boolean,
  url: string | null,
  toHref: (url: string) => string,
  label: string,
): { href: string; label: string } | null {
  return enabled && url !== null ? { href: toHref(url), label } : null;
}

export function WorkshopSubscription({
  view,
  actions,
  copy,
}: {
  view: WorkshopSessionView;
  actions: WorkshopSessionActions;
  copy: ReturnType<typeof t>;
}) {
  const assembled = view.assembled;
  const previewEnabled = view.previewReady;
  const url = assembled.url;
  const installLinks = [
    installLink(assembled.clashInstall, url, clashInstallUrl, copy.clashInstall),
    installLink(assembled.surgeInstall, url, surgeInstallUrl, copy.surgeInstall),
    installLink(assembled.loonInstall, url, loonInstallUrl, copy.loonInstall),
    installLink(assembled.egernInstall, url, egernInstallUrl, copy.egernInstall),
    installLink(assembled.singboxInstall, url, singboxInstallUrl, copy.singboxInstall),
  ].filter((item) => item !== null);

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
              value={assembled.url ?? ''}
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
            <details className="rounded-lg border bg-muted/30">
              <summary className="cursor-pointer px-3 py-2 text-sm font-medium">
                {copy.subscriptionTargets}
              </summary>
              <ul className="flex flex-col gap-px p-1">
                {assembled.siblings.map((sibling) => (
                  <li
                    key={sibling.target}
                    className="flex items-center gap-2 rounded-md px-2.5 py-1.5"
                  >
                    <span className="w-28 shrink-0 text-xs">
                      {copy.client[sibling.target].label}
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">
                      {sibling.url}
                    </span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`${copy.copyUrl} ${copy.client[sibling.target].label}`}
                      disabled={sibling.overLimit}
                      onClick={() => void actions.copy(sibling.url)}
                    >
                      <CopyIcon />
                    </Button>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </FieldGroup>
      </CardContent>
      <CardFooter>
        <Button
          type="button"
          onClick={() => void actions.copy()}
          disabled={assembled.url === null || assembled.overLimit}
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
        {installLinks.map((item) => (
          <Button
            key={item.label}
            nativeButton={false}
            variant="outline"
            render={<a href={item.href} />}
          >
            {item.label}
          </Button>
        ))}
      </CardFooter>
    </Card>
  );
}
