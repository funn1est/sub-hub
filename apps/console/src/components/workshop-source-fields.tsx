import { CircleAlertIcon, PlusIcon, Trash2Icon } from "lucide-react"

import { Alert, AlertDescription } from "@/components/ui/alert.tsx"
import { Button } from "@/components/ui/button.tsx"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field.tsx"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group.tsx"
import { t } from "@/lib/i18n.ts"
import {
  urlField,
  type PasteWarning,
  type WorkshopFields,
} from "@/lib/workshop.ts"
import type { WorkshopSessionActions } from "@/lib/workshop-session.ts"

export function SourceFields({
  fields,
  sourceInvalid,
  pasteWarnings,
  copy,
  actions,
}: {
  fields: WorkshopFields
  sourceInvalid: boolean[]
  pasteWarnings: readonly PasteWarning[]
  copy: ReturnType<typeof t>
  actions: WorkshopSessionActions
}) {
  return (
    <FieldGroup>
      {fields.sources.map((source, index) => {
        const invalid = sourceInvalid[index] === true
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
                onChange={(event) =>
                  actions.setSource(index, event.target.value)
                }
                onPaste={(event) => {
                  const field = event.currentTarget
                  const outcome = actions.pasteIntoSource(
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
                    onClick={() => actions.removeSource(index)}
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
        onClick={() => actions.addSource()}
      >
        <PlusIcon data-icon="inline-start" />
        {copy.addSource}
      </Button>
      {pasteWarnings.map((warning) => (
        <Alert key={warning}>
          <CircleAlertIcon />
          <AlertDescription>{copy.pasteWarnings[warning]}</AlertDescription>
        </Alert>
      ))}
    </FieldGroup>
  )
}
