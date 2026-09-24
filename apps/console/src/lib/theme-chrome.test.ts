import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

import {
  chromeFromPersistRaw,
  resolveDocumentLang,
  resolveTheme,
  themeColorMetas,
} from './theme-chrome.ts';

type ThemeColorShot = { content: string; media: string | null };

type BootShot = {
  lang: string;
  className: string[];
  themeColors: ThemeColorShot[];
};

const bootPath = resolve(import.meta.dirname, '../../public/theme-boot.js');
const indexPath = resolve(import.meta.dirname, '../../index.html');
const headersPath = resolve(import.meta.dirname, '../../public/_headers');

describe('chromeFromPersistRaw', () => {
  it('reads only top-level theme and locale from the persist blob', () => {
    expect(chromeFromPersistRaw(null)).toEqual({ theme: 'system', locale: undefined });
    expect(chromeFromPersistRaw('not-json')).toEqual({ theme: 'system', locale: undefined });
    expect(chromeFromPersistRaw('{"theme":"dark","locale":"zh"}')).toEqual({
      theme: 'dark',
      locale: 'zh',
    });
    expect(chromeFromPersistRaw('{"theme":"neon","locale":"de"}')).toEqual({
      theme: 'system',
      locale: undefined,
    });
    expect(chromeFromPersistRaw('{"state":{"theme":"dark","locale":"zh"}}')).toEqual({
      theme: 'system',
      locale: undefined,
    });
  });
});

describe('resolveTheme', () => {
  it('honors an explicit theme and otherwise follows prefers-color-scheme', () => {
    expect(resolveTheme('dark', false)).toBe('dark');
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('system', true)).toBe('dark');
    expect(resolveTheme('system', false)).toBe('light');
  });
});

describe('resolveDocumentLang', () => {
  it('uses a stored locale and otherwise follows navigator.language', () => {
    expect(resolveDocumentLang('zh', 'en-US')).toBe('zh-CN');
    expect(resolveDocumentLang('en', 'zh-CN')).toBe('en');
    expect(resolveDocumentLang(undefined, 'zh-CN')).toBe('zh-CN');
    expect(resolveDocumentLang(undefined, 'en-US')).toBe('en');
  });
});

describe('themeColorMetas', () => {
  it('uses one meta for an explicit theme and the docs media pair for system', () => {
    expect(themeColorMetas('light')).toEqual([{ content: '#fafafa' }]);
    expect(themeColorMetas('dark')).toEqual([{ content: '#0a0a0a' }]);
    expect(themeColorMetas('system')).toEqual([
      { content: '#fafafa', media: '(prefers-color-scheme: light)' },
      { content: '#0a0a0a', media: '(prefers-color-scheme: dark)' },
    ]);
  });
});

describe('theme-boot.js', () => {
  it('sets lang, html class, and theme-color before any React code runs', async () => {
    const source = await readFile(bootPath, 'utf8');

    expect(
      runThemeBoot(source, {
        raw: '{"theme":"dark","locale":"zh"}',
        prefersDark: false,
        language: 'en-US',
      }),
    ).toEqual({
      lang: 'zh-CN',
      className: ['dark'],
      themeColors: [{ content: '#0a0a0a', media: null }],
    });

    expect(
      runThemeBoot(source, {
        raw: '{"theme":"light","locale":"en"}',
        prefersDark: true,
        language: 'zh-CN',
      }),
    ).toEqual({
      lang: 'en',
      className: ['light'],
      themeColors: [{ content: '#fafafa', media: null }],
    });

    expect(
      runThemeBoot(source, {
        raw: null,
        prefersDark: true,
        language: 'zh-CN',
      }),
    ).toEqual({
      lang: 'zh-CN',
      className: ['dark'],
      themeColors: [
        { content: '#fafafa', media: '(prefers-color-scheme: light)' },
        { content: '#0a0a0a', media: '(prefers-color-scheme: dark)' },
      ],
    });
  });
});

describe('Console first-paint shell', () => {
  it('ships the docs theme-color pair, an external boot script, and an unchanged CSP', async () => {
    const html = await readFile(indexPath, 'utf8');
    const headers = await readFile(headersPath, 'utf8');

    expect(html).toContain(
      '<meta name="theme-color" content="#fafafa" media="(prefers-color-scheme: light)" />',
    );
    expect(html).toContain(
      '<meta name="theme-color" content="#0a0a0a" media="(prefers-color-scheme: dark)" />',
    );
    expect(html).toContain('<script src="/theme-boot.js"></script>');
    expect(html).not.toContain("script-src 'unsafe-inline'");
    expect(headers).toContain("script-src 'self'");
    expect(headers).not.toContain('unsafe-inline');
  });
});

function runThemeBoot(
  source: string,
  input: { raw: string | null; prefersDark: boolean; language: string },
): BootShot {
  type FakeMeta = {
    content: string;
    media: string | null;
    parentNode: { removeChild: (node: FakeMeta) => void };
  };

  const classes = new Set<string>();
  const state = { lang: 'en' };
  const metas: FakeMeta[] = [];

  const addMeta = (content: string, media: string | null) => {
    const meta: FakeMeta = {
      content,
      media,
      parentNode: {
        removeChild(node) {
          const index = metas.indexOf(node);
          if (index >= 0) {
            metas.splice(index, 1);
          }
        },
      },
    };
    metas.push(meta);
  };

  addMeta('#fafafa', '(prefers-color-scheme: light)');
  addMeta('#0a0a0a', '(prefers-color-scheme: dark)');

  const document = {
    documentElement: {
      get lang() {
        return state.lang;
      },
      set lang(value: string) {
        state.lang = value;
      },
      classList: {
        add(...tokens: string[]) {
          for (const token of tokens) {
            classes.add(token);
          }
        },
        remove(...tokens: string[]) {
          for (const token of tokens) {
            classes.delete(token);
          }
        },
      },
    },
    querySelectorAll(selector: string) {
      if (selector !== 'meta[name="theme-color"]') {
        return [];
      }
      return metas.slice();
    },
    createElement(tag: string) {
      if (tag !== 'meta') {
        throw new Error(tag);
      }
      const attrs: Record<string, string> = {};
      return {
        setAttribute(name: string, value: string) {
          attrs[name] = value;
        },
        attrs,
      };
    },
    head: {
      appendChild(node: { attrs: Record<string, string> }) {
        addMeta(node.attrs.content, node.attrs.media ?? null);
      },
    },
  };

  runInNewContext(source, {
    document,
    localStorage: {
      getItem(key: string) {
        return key === 'sub-hub.console.v1' ? input.raw : null;
      },
    },
    navigator: { language: input.language },
    window: {
      matchMedia(query: string) {
        return { matches: query === '(prefers-color-scheme: dark)' && input.prefersDark };
      },
    },
  });

  return {
    lang: state.lang,
    className: [...classes].sort(),
    themeColors: metas.map((meta) => ({ content: meta.content, media: meta.media })),
  };
}
