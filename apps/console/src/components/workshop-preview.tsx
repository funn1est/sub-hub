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
import {
  knownErrorTitle,
  omittedSummary,
  skippedSummary,
  t,
} from "@/lib/i18n.ts"
import type { Locale } from "@/lib/persist.ts"
import type { PreviewState } from "@/lib/preview.ts"

export function PreviewCard({
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
  const omitted = preview.omitted

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
          {omitted !== null ? (
            <Alert>
              <CircleAlertIcon />
              <AlertTitle>{copy.omitted}</AlertTitle>
              <AlertDescription>
                {omittedSummary(locale, omitted.omittedUrlRegex)}
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
