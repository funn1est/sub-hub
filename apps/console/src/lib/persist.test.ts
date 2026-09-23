import { describe, expect, it } from 'vitest';

import {
  composePersisted,
  defaultLocale,
  parsePersisted,
  PERSIST_KEY,
  readPersisted,
  serializePersisted,
  workshopFieldsOf,
  writePersisted,
  type PersistedWorkshop,
} from './persist.ts';

const sample: PersistedWorkshop = {
  locale: 'zh',
  theme: 'system',
  serviceOrigin: 'http://127.0.0.1:25500',
  accessToken: 'deployer-token_1',
  sources: ['vless://u@h:443#A'],
  target: 'clash',
  configUrl: '',
  appendInfo: true,
  expand: false,
  filename: '',
};

function memoryStorage(initial: Iterable<readonly [string, string]> = []) {
  const data = new Map<string, string>(initial);
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => {
      data.set(key, value);
    },
  };
}

describe('defaultLocale', () => {
  it('selects zh only when navigator.language starts with zh', () => {
    expect(defaultLocale('zh-CN')).toBe('zh');
    expect(defaultLocale('zh')).toBe('zh');
    expect(defaultLocale('en-US')).toBe('en');
    expect(defaultLocale('ja')).toBe('en');
  });
});

describe('persist', () => {
  it('round-trips the access token and never serializes a preview body', () => {
    const extra = {
      ...sample,
      previewBody: 'vless://uuid:password@secret.example:443',
    } as PersistedWorkshop & { previewBody: string };

    const raw = serializePersisted(extra);
    expect(raw).not.toContain('previewBody');
    expect(raw).not.toContain('uuid:password');
    expect(raw).not.toContain('secret.example');
    expect(JSON.parse(raw)).toEqual(sample);

    const storage = memoryStorage([[PERSIST_KEY, raw]]);
    const loaded = readPersisted(storage);
    expect(loaded.accessToken).toBe('deployer-token_1');
    expect(loaded).toEqual(sample);
    expect(loaded).not.toHaveProperty('previewBody');
  });

  it('round-trips more than five sources without truncating', () => {
    const six = {
      ...sample,
      sources: [
        'vless://u@h:443#A',
        'ss://p@h:8388#B',
        'vless://u@h:443#C',
        'vless://u@h:443#D',
        'vless://u@h:443#E',
        'vless://u@h:443#F',
      ],
    };
    const loaded = readPersisted(memoryStorage([[PERSIST_KEY, serializePersisted(six)]]));
    expect(loaded.sources).toEqual(six.sources);
  });

  it('falls back to defaults when the stored blob is missing or invalid', () => {
    const empty = readPersisted(memoryStorage(), {
      locale: 'en',
      serviceOrigin: 'http://127.0.0.1:25500',
    });
    expect(empty).toEqual({
      locale: 'en',
      theme: 'system',
      serviceOrigin: 'http://127.0.0.1:25500',
      accessToken: '',
      sources: [''],
      target: 'clash',
      configUrl: '',
      appendInfo: true,
      expand: true,
      filename: '',
    });

    const junk = readPersisted(memoryStorage([[PERSIST_KEY, 'not-json']]));
    expect(junk.target).toBe('clash');
    expect(junk.sources).toEqual(['']);
    expect(junk.accessToken).toBe('');
    expect(junk.expand).toBe(true);
  });

  it('treats a missing filename field as empty', () => {
    const { filename, ...withoutFilename } = sample;
    expect(filename).toBe('');
    const loaded = readPersisted(memoryStorage([[PERSIST_KEY, JSON.stringify(withoutFilename)]]));
    expect(loaded.filename).toBe('');
  });

  it('coerces a persisted mihomo target to the clash picker identity', () => {
    expect(parsePersisted(JSON.stringify({ ...sample, target: 'mihomo' })).target).toBe('clash');
  });

  it('rewrites a hydrated mihomo blob to clash on the next persist write', () => {
    const storage = memoryStorage([[PERSIST_KEY, JSON.stringify({ ...sample, target: 'mihomo' })]]);
    const loaded = readPersisted(storage);
    expect(loaded.target).toBe('clash');
    expect(JSON.parse(storage.data.get(PERSIST_KEY) ?? '').target).toBe('mihomo');
    writePersisted(storage, loaded);
    expect(JSON.parse(storage.data.get(PERSIST_KEY) ?? '').target).toBe('clash');
  });

  it('treats a missing expand field as the default on', () => {
    const { expand, ...withoutExpand } = sample;
    expect(expand).toBe(false);
    const loaded = readPersisted(memoryStorage([[PERSIST_KEY, JSON.stringify(withoutExpand)]]));
    expect(loaded.expand).toBe(true);
  });

  it("writes a flat PersistedWorkshop blob, not Zustand's {state, version} wrapper", () => {
    const storage = memoryStorage();
    writePersisted(storage, sample);
    const raw = storage.data.get(PERSIST_KEY);
    expect(raw).toBeDefined();
    const parsed = JSON.parse(raw ?? 'null') as unknown;
    expect(parsed).toEqual(sample);
    expect(parsed).not.toHaveProperty('state');
    expect(parsed).not.toHaveProperty('version');
  });

  it('strips a preview body when the written snapshot includes one', () => {
    const storage = memoryStorage();
    writePersisted(storage, {
      ...sample,
      previewBody: 'vless://uuid:password@secret.example:443',
    } as PersistedWorkshop & { previewBody: string });
    const raw = storage.data.get(PERSIST_KEY) ?? '';
    expect(raw).not.toContain('previewBody');
    expect(raw).not.toContain('uuid:password');
    expect(raw).not.toContain('secret.example');
    expect(JSON.parse(raw)).toEqual(sample);
  });

  it('splits conversion fields from Console chrome and composes them back', () => {
    expect(workshopFieldsOf(sample)).toEqual({
      serviceOrigin: sample.serviceOrigin,
      accessToken: sample.accessToken,
      sources: sample.sources,
      target: sample.target,
      configUrl: sample.configUrl,
      appendInfo: sample.appendInfo,
      expand: sample.expand,
      filename: sample.filename,
    });
    expect(
      composePersisted(workshopFieldsOf(sample), {
        locale: 'en',
        theme: 'dark',
      }),
    ).toEqual({ ...sample, locale: 'en', theme: 'dark' });
  });

  it('round-trips a Classic ACL4SSR config URL', () => {
    const classic =
      'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR.ini';
    const storage = memoryStorage();
    writePersisted(storage, { ...sample, configUrl: classic });
    expect(JSON.parse(storage.data.get(PERSIST_KEY) ?? '').configUrl).toBe(classic);
    expect(workshopFieldsOf(readPersisted(storage)).configUrl).toBe(classic);
  });
});
