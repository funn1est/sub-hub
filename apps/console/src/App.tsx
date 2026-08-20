import * as React from "react"
import { useRegisterSW } from "virtual:pwa-register/react"

import { ThemeProvider } from "@/components/theme-provider.tsx"
import { Workshop } from "@/components/workshop.tsx"
import { Alert, AlertAction, AlertTitle } from "@/components/ui/alert.tsx"
import { Button } from "@/components/ui/button.tsx"
import { t } from "@/lib/i18n.ts"
import {
  defaultLocale,
  loadPersisted,
  savePersisted,
  type PersistedWorkshop,
} from "@/lib/persist.ts"
import { parseServiceOrigin } from "@/lib/workshop.ts"

function initialState(): PersistedWorkshop {
  const envOrigin = parseServiceOrigin(
    import.meta.env.VITE_DEFAULT_SERVICE_ORIGIN ?? ""
  )
  return loadPersisted(window.localStorage, {
    locale: defaultLocale(navigator.language),
    serviceOrigin: envOrigin ?? "",
  })
}

export function App() {
  const [state, setState] = React.useState<PersistedWorkshop>(initialState)
  const copy = t(state.locale)
  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({ immediate: true })

  React.useEffect(() => {
    savePersisted(window.localStorage, state)
  }, [state])

  return (
    <ThemeProvider theme={state.theme}>
      <Workshop
        state={state}
        onChange={setState}
        banner={
          needRefresh ? (
            <Alert>
              <AlertTitle>{copy.pwaUpdate}</AlertTitle>
              <AlertAction>
                <Button
                  size="sm"
                  onClick={() => {
                    void updateServiceWorker(true)
                    setNeedRefresh(false)
                  }}
                >
                  {copy.pwaReload}
                </Button>
              </AlertAction>
            </Alert>
          ) : null
        }
      />
    </ThemeProvider>
  )
}

export default App
