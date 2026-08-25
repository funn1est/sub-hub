import * as React from "react"
import { useRegisterSW } from "virtual:pwa-register/react"

import { ConsoleChromeBar } from "@/components/console-chrome.tsx"
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
  const [boot] = React.useState(loadInitial)
  const [notifyPort] = React.useState(() => createNotifyPort(boot.locale))
  const [session] = React.useState(() =>
    createWorkshopSession({
      initialFields: workshopFieldsOf(boot),
      env: {
        pageHttps: window.location.protocol === "https:",
        consoleOrigin: import.meta.env.DEV
          ? undefined
          : (parseServiceOrigin(window.location.origin) ?? undefined),
      },
      ports: {
        notify: notifyPort.notify,
      },
    })
  )
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
    notifyPort.setLocale(chrome.locale)
  }, [chrome.locale, notifyPort])

  React.useEffect(() => {
    savePersisted(window.localStorage, composePersisted(view.fields, chrome))
  }, [chrome, view.fields])

  React.useEffect(() => {
    document.documentElement.lang = chrome.locale === "zh" ? "zh-CN" : "en"
    document.title = copy.title
  }, [chrome.locale, copy.title])

  return (
    <ThemeProvider theme={chrome.theme}>
      <div className="console-shell relative isolate">
        <div className="console-shell-bg" aria-hidden />
        <ConsoleChromeBar
          locale={chrome.locale}
          theme={chrome.theme}
          onLocaleChange={(locale) =>
            setChrome((current) => ({ ...current, locale }))
          }
          onThemeChange={(theme) =>
            setChrome((current) => ({ ...current, theme }))
          }
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
        <Workshop
          view={view}
          actions={session.actions}
          locale={chrome.locale}
        />
      </div>
    </ThemeProvider>
  )
}

export default App
