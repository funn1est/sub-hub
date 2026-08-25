import { Settings2Icon } from "lucide-react"

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
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field.tsx"
import { InputGroup, InputGroupInput } from "@/components/ui/input-group.tsx"
import { Switch } from "@/components/ui/switch.tsx"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group.tsx"
import { t } from "@/lib/i18n.ts"
import type { WorkshopFields } from "@/lib/persist.ts"
import { TARGETS, isTarget } from "@/lib/service-contract.ts"
import {
  type ConfigChoice,
  type ConfigChoiceGroup,
} from "@/lib/workshop-config.ts"
import type { WorkshopSessionActions } from "@/lib/workshop-session.ts"
import { SectionCard } from "@/components/workshop-section.tsx"

const urlField = {
  inputMode: "url" as const,
  autoCapitalize: "none" as const,
  autoCorrect: "off" as const,
  spellCheck: false,
}

export function WorkshopOptions({
  fields,
  configInvalid,
  showCustomConfigField,
  configGroups,
  selectedConfig,
  copy,
  actions,
}: {
  fields: WorkshopFields
  configInvalid: boolean
  showCustomConfigField: boolean
  configGroups: ConfigChoiceGroup[]
  selectedConfig: ConfigChoice
  copy: ReturnType<typeof t>
  actions: WorkshopSessionActions
}) {
  return (
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
                actions.patch({ target: next })
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
              actions.selectConfig(item.id)
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
        {showCustomConfigField ? (
          <Field data-invalid={configInvalid || undefined}>
            <FieldLabel htmlFor="config-url">{copy.configUrl}</FieldLabel>
            <InputGroup>
              <InputGroupInput
                id="config-url"
                value={fields.configUrl}
                enterKeyHint="done"
                aria-invalid={configInvalid || undefined}
                placeholder="https://"
                {...urlField}
                onChange={(event) =>
                  actions.editCustomConfigUrl(event.target.value)
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
              actions.patch({ appendInfo: checked })
            }
          />
        </Field>
      </FieldGroup>
    </SectionCard>
  )
}
