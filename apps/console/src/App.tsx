import * as React from "react"
import { useRegisterSW } from "virtual:pwa-register/react"
import { useStore } from "zustand/react"

import { ConsoleChromeBar } from "@/components/console-chrome.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"
import { Workshop } from "@/components/workshop.tsx"
import { Alert, AlertAction, AlertTitle } from "@/components/ui/alert.tsx"
import { Button } from "@/components/ui/button.tsx"
import { toast } from "@/components/ui/toast.tsx"
import { t } from "@/lib/i18n.ts"
import {
  createConsolePersist,
  defaultLocale,
  workshopFieldsOf,
  type Locale,
} from "@/lib/persist.ts"
import {
  createWorkshopSession,
  type WorkshopNotice,
} from "@/lib/workshop-session.ts"
import { parseServiceOrigin } from "@/lib/workshop.ts"

function createPersist() {
  const envOrigin = parseServiceOrigin(
    import.meta.env.VITE_DEFAULT_SERVICE_ORIGIN ?? ""
  )
  return createConsolePersist(window.localStorage, {
    locale: defaultLocale(navigator.language),
    serviceOrigin: envOrigin ?? "",
  })
}

function toastNotice(locale: Locale, notice: WorkshopNotice) {
  const copy = t(locale)
  if (notice === "copied") {
    toast.add({ type: "success", title: copy.copied })
    return
  }
  if (notice === "paste-failed") {
    toast.add({ type: "error", title: copy.pasteFailed })
    return
  }
  toast.add({ type: "error", title: copy.copyFailed })
}

function createNotifyPort(initial: Locale) {
  let locale = initial
  return {
    setLocale(next: Locale) {
      locale = next
    },
    notify(notice: WorkshopNotice) {
      toastNotice(locale, notice)
    },
  }
}

export function App() {
  const [workshopPersist] = React.useState(() => createPersist())
  const locale = useStore(workshopPersist, (state) => state.locale)
  const theme = useStore(workshopPersist, (state) => state.theme)
  const [notifyPort] = React.useState(() =>
    createNotifyPort(workshopPersist.getState().locale)
  )
  const [session] = React.useState(() =>
    createWorkshopSession({
      initialFields: workshopFieldsOf(workshopPersist.getState()),
      env: {
        pageHttps: window.location.protocol === "https:",
        consoleOrigin: import.meta.env.DEV
          ? undefined
          : (parseServiceOrigin(window.location.origin) ?? undefined),
        userAgent: navigator.userAgent,
      },
      ports: {
        notify: notifyPort.notify,
      },
    })
  )
  const view = React.useSyncExternalStore(
    session.subscribe,
    session.getView,
    session.getView
  )
  const copy = t(locale)
  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({ immediate: true })

  React.useEffect(() => {
    notifyPort.setLocale(locale)
  }, [locale, notifyPort])

  React.useEffect(() => {
    workshopPersist.setState(view.fields)
  }, [view.fields, workshopPersist])

  React.useEffect(() => {
    document.documentElement.lang = locale === "zh" ? "zh-CN" : "en"
    document.title = copy.title
  }, [locale, copy.title])

  return (
    <ThemeProvider theme={theme}>
      <div className="console-shell relative isolate">
        <div className="console-shell-bg" aria-hidden />
        <ConsoleChromeBar
          locale={locale}
          theme={theme}
          onLocaleChange={(next) => workshopPersist.setState({ locale: next })}
          onThemeChange={(next) => workshopPersist.setState({ theme: next })}
        />
        {needRefresh ? (
          <div className="mx-auto w-full max-w-3xl px-4 pt-6 sm:px-6">
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
          </div>
        ) : null}
        <Workshop view={view} actions={session.actions} locale={locale} />
      </div>
    </ThemeProvider>
  )
}

export default App
