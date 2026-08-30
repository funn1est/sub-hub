import * as React from "react"

import { SOURCE_REPO, t } from "@/lib/i18n.ts"
import type { Locale } from "@/lib/persist.ts"
import {
  configChoiceGroups,
  selectedConfigChoice,
} from "@/lib/workshop-config.ts"
import type {
  WorkshopSessionActions,
  WorkshopSessionView,
} from "@/lib/workshop-session.ts"
import { PreviewCard } from "@/components/workshop-preview.tsx"
import { WorkshopOptions } from "@/components/workshop-options.tsx"
import { WorkshopService } from "@/components/workshop-service.tsx"
import { WorkshopSources } from "@/components/workshop-sources.tsx"
import { WorkshopSubscription } from "@/components/workshop-subscription.tsx"

type WorkshopProps = {
  view: WorkshopSessionView
  actions: WorkshopSessionActions
  locale: Locale
}

export function Workshop({ view, actions, locale }: WorkshopProps) {
  const copy = t(locale)
  const fields = view.fields
  const previewEnabled = view.previewReady
  const configGroups = React.useMemo(() => configChoiceGroups(copy), [copy])
  const selectedConfig = selectedConfigChoice(
    configGroups,
    view.configSelection
  )

  return (
    <main
      className="mx-auto flex w-full max-w-3xl min-w-0 flex-col gap-5 px-4 py-6 pb-[max(1.5rem,env(safe-area-inset-bottom))] sm:px-6"
      onKeyDown={(event) => {
        if (
          (event.metaKey || event.ctrlKey) &&
          event.key === "Enter" &&
          previewEnabled
        ) {
          event.preventDefault()
          void actions.preview()
        }
      }}
    >
      <WorkshopService view={view} actions={actions} copy={copy} />
      <WorkshopSources
        fields={fields}
        sourceInvalid={view.sourceInvalid}
        copy={copy}
        actions={actions}
      />
      <WorkshopOptions
        fields={fields}
        configInvalid={view.configInvalid}
        filenameInvalid={view.filenameInvalid}
        showCustomConfigField={view.configSelection === "custom"}
        configGroups={configGroups}
        selectedConfig={selectedConfig}
        copy={copy}
        locale={locale}
        actions={actions}
      />
      <WorkshopSubscription view={view} actions={actions} copy={copy} />
      <PreviewCard
        locale={locale}
        preview={view.preview}
        copy={copy}
        onDownload={actions.download}
      />
      <p className="pb-4 text-center text-xs text-muted-foreground">
        <a href={SOURCE_REPO} className="underline underline-offset-2">
          {copy.agpl}
        </a>
      </p>
    </main>
  )
}
