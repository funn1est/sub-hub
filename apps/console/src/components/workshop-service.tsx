import * as React from "react"
import { EyeIcon, EyeOffIcon, ServerIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge.tsx"
import { Button } from "@/components/ui/button.tsx"
import {
  Card,
  CardAction,
  CardContent,
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
import { t } from "@/lib/i18n.ts"
import type {
  WorkshopSessionActions,
  WorkshopSessionView,
} from "@/lib/workshop-session.ts"
import { urlField } from "@/lib/workshop.ts"
import {
  SectionHeading,
  VersionAlert,
  VersionBadge,
} from "@/components/workshop-section.tsx"

export function WorkshopService({
  view,
  actions,
  copy,
}: {
  view: WorkshopSessionView
  actions: WorkshopSessionActions
  copy: ReturnType<typeof t>
}) {
  const fields = view.fields
  const canCollapseService = view.serviceCollapsible
  const [revealToken, setRevealToken] = React.useState(false)
  const [serviceOpen, setServiceOpen] = React.useState(
    () => view.canonicalOrigin === null
  )
  const showServiceFields = serviceOpen || !canCollapseService

  return (
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
              <FieldLabel htmlFor="access-token">{copy.accessToken}</FieldLabel>
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
  )
}
