import { Link2Icon } from "lucide-react"

import { t } from "@/lib/i18n.ts"
import type { WorkshopSessionActions } from "@/lib/workshop-session.ts"
import type { WorkshopFields } from "@/lib/workshop.ts"
import { SectionCard } from "@/components/workshop-section.tsx"
import { SourceFields } from "@/components/workshop-source-fields.tsx"

export function WorkshopSources({
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
    <SectionCard
      icon={<Link2Icon />}
      title={copy.sources}
      description={copy.sourcesDescription}
    >
      <SourceFields
        fields={fields}
        sourceInvalid={sourceInvalid}
        copy={copy}
        actions={actions}
      />
    </SectionCard>
  )
}
