import {
  ACL4SSR_FAMILIES,
  ACL4SSR_PRESETS,
  acl4ssrConfigLabel,
  type Acl4ssrPreset,
  type ConfigSelectionId,
} from "./acl4ssr-catalog.ts"
import type { Messages } from "./i18n.ts"

export type ConfigChoice = {
  id: ConfigSelectionId
  label: string
  detail?: string
  search: string
}

export type ConfigChoiceGroup = {
  value: string
  items: ConfigChoice[]
}

function presetChoice(copy: Messages, preset: Acl4ssrPreset): ConfigChoice {
  const stem = acl4ssrConfigLabel(preset.file)
  const label = copy.configEffects[preset.effect]
  return {
    id: preset.file,
    label,
    detail: stem,
    search: `${label} ${stem} ${preset.file}`,
  }
}

function plainChoice(
  id: Extract<ConfigSelectionId, "none" | "custom">,
  label: string,
  search: string
): ConfigChoice {
  return { id, label, search }
}

export function configChoiceGroups(copy: Messages): ConfigChoiceGroup[] {
  return [
    {
      value: copy.configNone,
      items: [
        plainChoice("none", copy.configNone, `${copy.configNone} PROXY AUTO`),
      ],
    },
    ...ACL4SSR_FAMILIES.map((family) => ({
      value: copy.configFamilies[family],
      items: ACL4SSR_PRESETS[family].map((preset) =>
        presetChoice(copy, preset)
      ),
    })),
    {
      value: copy.configCustom,
      items: [plainChoice("custom", copy.configCustom, copy.configCustom)],
    },
  ]
}

export function selectedConfigChoice(
  groups: readonly ConfigChoiceGroup[],
  id: ConfigSelectionId
): ConfigChoice {
  for (const group of groups) {
    const found = group.items.find((item) => item.id === id)
    if (found !== undefined) {
      return found
    }
  }
  const fallback = groups[0]?.items[0]
  return fallback ?? { id: "none", label: "", search: "" }
}
