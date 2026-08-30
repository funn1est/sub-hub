import * as React from "react"
import { CircleAlertIcon } from "lucide-react"

import { Alert, AlertTitle } from "@/components/ui/alert.tsx"
import { Badge } from "@/components/ui/badge.tsx"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.tsx"
import { Spinner } from "@/components/ui/spinner.tsx"
import { t } from "@/lib/i18n.ts"
import type { VersionState } from "@/lib/preview.ts"

export function SectionCard({
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

export function SectionHeading({
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

export function VersionBadge({
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
      <Badge
        variant="secondary"
        className="max-w-full truncate"
        aria-label={copy.versionOk}
      >
        {state.body}
      </Badge>
    )
  }
  return <Badge variant="destructive">{copy.versionIssue}</Badge>
}

export function VersionAlert({
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
