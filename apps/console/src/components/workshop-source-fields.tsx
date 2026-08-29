import {
  ClipboardPasteIcon,
  EraserIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react"

import { Button } from "@/components/ui/button.tsx"
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field.tsx"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group.tsx"
import { t } from "@/lib/i18n.ts"
import { urlField, type WorkshopFields } from "@/lib/workshop.ts"
import type { WorkshopSessionActions } from "@/lib/workshop-session.ts"

export function SourceFields({
  fields,
  sourceInvalid,
  copy,
  actions,
}: {
  fields: WorkshopFields
  sourceInvalid: boolean[]
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
                  const text = event.clipboardData.getData("text")
                  if (!text.includes("\n") && !text.includes("|")) {
                    return
                  }
                  event.preventDefault()
                  actions.setSourceFromPaste(index, text)
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
      <div className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={() => actions.clearSources()}
        >
          <EraserIcon data-icon="inline-start" />
          {copy.clearSources}
        </Button>
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={() => {
            void actions.pasteSourcesFromClipboard()
          }}
        >
          <ClipboardPasteIcon data-icon="inline-start" />
          {copy.pasteSources}
        </Button>
      </div>
      <Button
        type="button"
        variant="outline"
        className="w-full"
        onClick={() => actions.addSource()}
      >
        <PlusIcon data-icon="inline-start" />
        {copy.addSource}
      </Button>
    </FieldGroup>
  )
}
