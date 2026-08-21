import * as React from "react"
import { useRegisterSW } from "virtual:pwa-register/react"

import { ThemeProvider } from "@/components/theme-provider.tsx"
import { Workshop } from "@/components/workshop.tsx"
import { Alert, AlertAction, AlertTitle } from "@/components/ui/alert.tsx"
import { Button } from "@/components/ui/button.tsx"
import { toast } from "@/components/ui/toast.tsx"
import { t } from "@/lib/i18n.ts"
import {
  composePersisted,
  defaultLocale,
  loadPersisted,
  savePersisted,
  workshopFieldsOf,
  type ConsoleChrome,
  type Locale,
} from "@/lib/persist.ts"
import {
  createWorkshopSession,
  type WorkshopNotice,
  type WorkshopSession,
} from "@/lib/workshop-session.ts"
import { parseServiceOrigin } from "@/lib/workshop.ts"

function loadInitial() {
  const envOrigin = parseServiceOrigin(
    import.meta.env.VITE_DEFAULT_SERVICE_ORIGIN ?? ""
  )
  return loadPersisted(window.localStorage, {
    locale: defaultLocale(navigator.language),
    serviceOrigin: envOrigin ?? "",
  })
}

function toastNotice(locale: Locale, notice: WorkshopNotice) {
  const copy = t(locale)
  if (notice === "imported") {
    toast.add({ type: "success", title: copy.imported })
    return
  }
  if (notice === "copied") {
    toast.add({ type: "success", title: copy.copied })
    return
  }
  toast.add({ type: "error", title: copy.copyFailed })
}

type BootSession = {
  session: WorkshopSession
  setNotifyLocale: (locale: Locale) => void
}

export function App() {
  const [boot] = React.useState(loadInitial)
  const [bootSession] = React.useState<BootSession>(() => {
    let locale = boot.locale
    return {
      session: createWorkshopSession({
        initialFields: workshopFieldsOf(boot),
        env: {
          pageHttps: window.location.protocol === "https:",
          consoleOrigin: import.meta.env.DEV
            ? undefined
            : (parseServiceOrigin(window.location.origin) ?? undefined),
        },
        ports: {
          notify: (notice) => toastNotice(locale, notice),
        },
      }),
      setNotifyLocale: (next) => {
        locale = next
      },
    }
  })
  const session = bootSession.session
  const [chrome, setChrome] = React.useState<ConsoleChrome>({
    locale: boot.locale,
    theme: boot.theme,
  })
  const view = React.useSyncExternalStore(
    session.subscribe,
    session.getView,
    session.getView
  )
  const copy = t(chrome.locale)
  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({ immediate: true })

  React.useEffect(() => {
    bootSession.setNotifyLocale(chrome.locale)
  }, [bootSession, chrome.locale])

  React.useEffect(() => {
    savePersisted(window.localStorage, composePersisted(view.fields, chrome))
  }, [chrome, view.fields])

  React.useEffect(() => {
    document.documentElement.lang = chrome.locale === "zh" ? "zh-CN" : "en"
    document.title = copy.title
  }, [chrome.locale, copy.title])

  return (
    <ThemeProvider theme={chrome.theme}>
      <Workshop
        session={session}
        locale={chrome.locale}
        theme={chrome.theme}
        onLocaleChange={(locale) => {
          bootSession.setNotifyLocale(locale)
          setChrome((current) => ({ ...current, locale }))
        }}
        onThemeChange={(theme) =>
          setChrome((current) => ({ ...current, theme }))
        }
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
