import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

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

function triggerButtons(html: string): string[] {
  return [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map((match) => match[0]);
}

describe('LocaleMenu trigger', () => {
  it('announces the language purpose on the closed trigger in en and zh', () => {
    const cases = [
      { locale: 'en' as const, current: 'EN', purpose: 'Language' },
      { locale: 'zh' as const, current: '中文', purpose: '语言' },
    ];

    for (const { locale, current, purpose } of cases) {
      const localeTrigger = triggerButtons(chromeMarkup(locale)).find((button) =>
        button.includes(current),
      );
      if (localeTrigger === undefined) {
        throw new Error(`missing locale trigger for ${locale}`);
      }
      expect(localeTrigger).toContain(current);
      expect(localeTrigger).toContain('sr-only');
      expect(localeTrigger).toContain(purpose);
    }
  });
});
