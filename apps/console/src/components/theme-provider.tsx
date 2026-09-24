import * as React from 'react';

import type { Theme } from '@/lib/persist.ts';
import { resolveTheme, themeColorMetas, type ThemeColorMeta } from '@/lib/theme-chrome.ts';

const COLOR_SCHEME_QUERY = '(prefers-color-scheme: dark)';

function prefersColorSchemeDark(): boolean {
  return window.matchMedia(COLOR_SCHEME_QUERY).matches;
}

function disableTransitionsTemporarily() {
  const root = document.documentElement;
  root.classList.add('theme-switching');

  return () => {
    window.getComputedStyle(document.body);
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        root.classList.remove('theme-switching');
      });
    });
  };
}

function replaceThemeColorMetas(metas: readonly ThemeColorMeta[]) {
  for (const node of document.querySelectorAll('meta[name="theme-color"]')) {
    node.remove();
  }
  for (const entry of metas) {
    const meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    meta.setAttribute('content', entry.content);
    if (entry.media !== undefined) {
      meta.setAttribute('media', entry.media);
    }
    document.head.appendChild(meta);
  }
}

export function ThemeProvider({ theme, children }: { theme: Theme; children: React.ReactNode }) {
  const applyTheme = React.useCallback((nextTheme: Theme) => {
    const root = document.documentElement;
    const resolvedTheme = resolveTheme(nextTheme, prefersColorSchemeDark());
    const restoreTransitions = disableTransitionsTemporarily();
    root.classList.remove('light', 'dark');
    root.classList.add(resolvedTheme);
    replaceThemeColorMetas(themeColorMetas(nextTheme));
    restoreTransitions();
  }, []);

  React.useEffect(() => {
    applyTheme(theme);
    if (theme !== 'system') {
      return undefined;
    }

    const mediaQuery = window.matchMedia(COLOR_SCHEME_QUERY);
    const handleChange = () => {
      applyTheme('system');
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => {
      mediaQuery.removeEventListener('change', handleChange);
    };
  }, [theme, applyTheme]);

  return children;
}
