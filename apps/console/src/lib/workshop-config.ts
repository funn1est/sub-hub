import {
  ACL4SSR_FULL_FILES,
  ACL4SSR_MINI_FILES,
  ACL4SSR_ONLINE_FILES,
  acl4ssrConfigLabel,
  type ConfigSelectionId,
} from "./acl4ssr-catalog.ts"
import type { Messages } from "./i18n.ts"

export type ConfigChoice = {
  id: ConfigSelectionId
  label: string
}

export type ConfigChoiceGroup = {
  value: string
  items: ConfigChoice[]
}

export function configChoiceGroups(copy: Messages): ConfigChoiceGroup[] {
  return [
    {
      value: copy.configNone,
      items: [{ id: "none", label: copy.configNone }],
    },
    {
      value: copy.configOnline,
      items: ACL4SSR_ONLINE_FILES.map((file) => ({
        id: file,
        label: acl4ssrConfigLabel(file),
      })),
    },
    {
      value: copy.configMini,
      items: ACL4SSR_MINI_FILES.map((file) => ({
        id: file,
        label: acl4ssrConfigLabel(file),
      })),
    },
    {
      value: copy.configFull,
      items: ACL4SSR_FULL_FILES.map((file) => ({
        id: file,
        label: acl4ssrConfigLabel(file),
      })),
    },
    {
      value: copy.configCustom,
      items: [{ id: "custom", label: copy.configCustom }],
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
  return fallback ?? { id: "none", label: "" }
}
