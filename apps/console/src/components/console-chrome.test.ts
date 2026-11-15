import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { t } from '@/lib/i18n.ts';

import { ConsoleChromeBar } from './console-chrome.tsx';

function chromeMarkup(locale: 'en' | 'zh'): string {
  return renderToStaticMarkup(
    createElement(ConsoleChromeBar, {
      locale,
      theme: 'system',
      onLocaleChange() {},
      onThemeChange() {},
    }),
  );
}

describe('LocaleMenu trigger', () => {
  it('names the language purpose on the closed trigger in en and zh', () => {
    for (const locale of ['en', 'zh'] as const) {
      const visible = locale === 'zh' ? '中文' : 'EN';
      expect(chromeMarkup(locale)).toContain(
        `${visible}<span class="sr-only">${t(locale).language}</span>`,
      );
    }
  });
});
