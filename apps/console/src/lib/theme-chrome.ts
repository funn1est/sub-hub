import type { Locale, Theme } from './persist.ts';

export const THEME_COLOR_LIGHT = '#fafafa';
export const THEME_COLOR_DARK = '#0a0a0a';

export type ResolvedTheme = 'dark' | 'light';

export type ThemeColorMeta = {
  content: string;
  media?: string;
};

export function chromeFromPersistRaw(raw: string | null): {
  theme: Theme;
  locale: Locale | undefined;
} {
  if (raw === null) {
    return { theme: 'system', locale: undefined };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { theme: 'system', locale: undefined };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { theme: 'system', locale: undefined };
  }

  const value = parsed as Record<string, unknown>;
  return {
    theme:
      value.theme === 'light' || value.theme === 'dark' || value.theme === 'system'
        ? value.theme
        : 'system',
    locale: value.locale === 'zh' || value.locale === 'en' ? value.locale : undefined,
  };
}

export function resolveTheme(theme: Theme, prefersDark: boolean): ResolvedTheme {
  if (theme === 'light' || theme === 'dark') {
    return theme;
  }
  return prefersDark ? 'dark' : 'light';
}

export function resolveDocumentLang(locale: Locale | undefined, language: string): 'zh-CN' | 'en' {
  if (locale === 'zh') {
    return 'zh-CN';
  }
  if (locale === 'en') {
    return 'en';
  }
  return language.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en';
}

export function themeColorMetas(theme: Theme): readonly ThemeColorMeta[] {
  if (theme === 'light') {
    return [{ content: THEME_COLOR_LIGHT }];
  }
  if (theme === 'dark') {
    return [{ content: THEME_COLOR_DARK }];
  }
  return [
    { content: THEME_COLOR_LIGHT, media: '(prefers-color-scheme: light)' },
    { content: THEME_COLOR_DARK, media: '(prefers-color-scheme: dark)' },
  ];
}
