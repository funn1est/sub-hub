import type { Theme } from './persist.ts';

const THEME_COLOR_LIGHT = '#fafafa';
const THEME_COLOR_DARK = '#0a0a0a';

export type ResolvedTheme = 'dark' | 'light';

export type ThemeColorMeta = {
  content: string;
  media?: string;
};

export function resolveTheme(theme: Theme, prefersDark: boolean): ResolvedTheme {
  if (theme === 'light' || theme === 'dark') {
    return theme;
  }
  return prefersDark ? 'dark' : 'light';
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
