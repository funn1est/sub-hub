import * as React from 'react';
import { useRegisterSW } from 'virtual:pwa-register/react';

import { ConsoleChromeBar } from '@/components/console-chrome.tsx';
import { ThemeProvider } from '@/components/theme-provider.tsx';
import { Workshop } from '@/components/workshop.tsx';
import { Alert, AlertAction, AlertTitle } from '@/components/ui/alert.tsx';
import { Button } from '@/components/ui/button.tsx';
import { toast } from '@/components/ui/toast.tsx';
import { t } from '@/lib/i18n.ts';
import {
  composePersisted,
  defaultLocale,
  readPersisted,
  workshopFieldsOf,
  writePersisted,
  type Locale,
} from '@/lib/persist.ts';
import { createWorkshopSession, type WorkshopNotice } from '@/lib/workshop-session.ts';
import { parseServiceOrigin } from '@/lib/workshop.ts';

function toastNotice(locale: Locale, notice: WorkshopNotice) {
  const copy = t(locale);
  if (notice === 'copied') {
    toast.add({ type: 'success', title: copy.copied });
    return;
  }
  if (notice === 'paste-failed') {
    toast.add({ type: 'error', title: copy.pasteFailed });
    return;
  }
  toast.add({ type: 'error', title: copy.copyFailed });
}

function createSession() {
  const envOrigin = parseServiceOrigin(import.meta.env.VITE_DEFAULT_SERVICE_ORIGIN ?? '');
  const persisted = readPersisted(window.localStorage, {
    locale: defaultLocale(navigator.language),
    serviceOrigin: envOrigin ?? '',
  });
  const session = createWorkshopSession({
    initialFields: workshopFieldsOf(persisted),
    initialChrome: { locale: persisted.locale, theme: persisted.theme },
    env: {
      pageHttps: window.location.protocol === 'https:',
      consoleOrigin: import.meta.env.DEV
        ? undefined
        : (parseServiceOrigin(window.location.origin) ?? undefined),
      userAgent: navigator.userAgent,
    },
    ports: {
      notify: (notice) => toastNotice(session.getView().locale, notice),
    },
  });
  return session;
}

export function App() {
  const [session] = React.useState(createSession);
  const view = React.useSyncExternalStore(session.subscribe, session.getView, session.getView);
  const copy = t(view.locale);
  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({ immediate: true });

  React.useEffect(() => {
    return session.subscribe(() => {
      const next = session.getView();
      writePersisted(
        window.localStorage,
        composePersisted(next.fields, { locale: next.locale, theme: next.theme }),
      );
    });
  }, [session]);

  React.useEffect(() => {
    document.documentElement.lang = view.locale === 'zh' ? 'zh-CN' : 'en';
    document.title = copy.title;
  }, [view.locale, copy.title]);

  return (
    <ThemeProvider theme={view.theme}>
      <div className="console-shell">
        <ConsoleChromeBar
          locale={view.locale}
          theme={view.theme}
          onLocaleChange={session.actions.setLocale}
          onThemeChange={session.actions.setTheme}
        />
        {needRefresh ? (
          <div className="mx-auto w-full max-w-3xl px-4 pt-6 sm:px-6">
            <Alert>
              <AlertTitle>{copy.pwaUpdate}</AlertTitle>
              <AlertAction>
                <Button
                  size="sm"
                  onClick={() => {
                    void updateServiceWorker(true);
                    setNeedRefresh(false);
                  }}
                >
                  {copy.pwaReload}
                </Button>
              </AlertAction>
            </Alert>
          </div>
        ) : null}
        <Workshop view={view} actions={session.actions} locale={view.locale} />
      </div>
    </ThemeProvider>
  );
}

export default App;
