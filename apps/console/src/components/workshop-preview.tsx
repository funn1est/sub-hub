import {
  CircleAlertIcon,
  DownloadIcon,
  FileCode2Icon,
  ShieldAlertIcon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx"
import { Button } from "@/components/ui/button.tsx"
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card.tsx"
import { ScrollArea } from "@/components/ui/scroll-area.tsx"
import { Spinner } from "@/components/ui/spinner.tsx"
import { SectionHeading } from "@/components/workshop-section.tsx"
import { t } from "@/lib/i18n.ts"
import type { Locale } from "@/lib/persist.ts"
import { previewProfile } from "@/lib/preview-copy.ts"
import type { PreviewState } from "@/lib/preview.ts"
import type { ClientTarget } from "@/lib/workshop.ts"

export function PreviewCard({
  locale,
  preview,
  copy,
  target,
  onDownload,
}: {
  locale: Locale
  preview: PreviewState
  copy: ReturnType<typeof t>
  target: ClientTarget
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

  const profile = previewProfile(locale, preview, target)

  return (
    <Card>
      <CardHeader className="border-b">
        <SectionHeading icon={<FileCode2Icon />} title={copy.preview} />
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4">
          {profile.error !== null ? (
            <Alert variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>{profile.error.heading}</AlertTitle>
              {profile.error.wire !== null ? (
                <AlertDescription className="font-mono">
                  {profile.error.wire}
                </AlertDescription>
              ) : null}
            </Alert>
          ) : null}
          {profile.traffic !== undefined ? (
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium">{copy.traffic}</p>
              <p className="text-sm">{profile.traffic.summary}</p>
              {profile.traffic.expire !== undefined ? (
                <p className="text-sm text-muted-foreground">
                  {profile.traffic.expire}
                </p>
              ) : null}
            </div>
          ) : null}
          {profile.skipped !== undefined ? (
            <Alert>
              <CircleAlertIcon />
              <AlertTitle>{copy.skipped}</AlertTitle>
              <AlertDescription>{profile.skipped}</AlertDescription>
            </Alert>
          ) : null}
          {profile.omitted !== undefined ? (
            <Alert>
              <CircleAlertIcon />
              <AlertTitle>{copy.omitted}</AlertTitle>
              <AlertDescription>{profile.omitted}</AlertDescription>
            </Alert>
          ) : null}
          {profile.capability !== undefined ? (
            <p className="text-sm text-muted-foreground">{profile.capability}</p>
          ) : null}
          <Alert>
            <ShieldAlertIcon />
            <AlertTitle>{copy.secretWarning}</AlertTitle>
          </Alert>
          <details className="rounded-lg border bg-muted/30">
            <summary className="cursor-pointer px-3 py-2 text-sm font-medium">
              {copy.body}
              {preview.truncated ? (
                <span className="ml-2 font-normal text-muted-foreground">
                  {copy.truncated}
                </span>
              ) : null}
            </summary>
            <ScrollArea className="h-[min(20rem,50svh)] border-t">
              <pre className="p-3 font-mono text-xs break-all whitespace-pre-wrap">
                {preview.viewText}
              </pre>
            </ScrollArea>
          </details>
          {preview.headers.length > 0 ? (
            <details className="rounded-lg border bg-muted/30">
              <summary className="cursor-pointer px-3 py-2 text-sm font-medium">
                {copy.headers}
              </summary>
              <ul className="flex flex-col gap-px p-1">
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
            </details>
          ) : null}
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
