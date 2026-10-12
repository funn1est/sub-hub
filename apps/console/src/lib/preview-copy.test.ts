import { describe, expect, it } from 'vitest';

import { messages } from './i18n.ts';
import { previewProfile } from './preview-copy.ts';
import type { PreviewDone } from './preview.ts';

function done(partial: Partial<PreviewDone> & Pick<PreviewDone, 'body'>): PreviewDone {
  return {
    status: 'done',
    httpStatus: 200,
    kind: { kind: 'ok' },
    headers: [],
    skipped: null,
    omitted: null,
    traffic: null,
    viewText: partial.body,
    truncated: false,
    filename: 'sub-hub-mihomo.yaml',
    ...partial,
  };
}

describe('previewProfile', () => {
  it('uses binary units in traffic copy', () => {
    expect(
      previewProfile(
        'en',
        done({
          body: 'mode: rule\n',
          traffic: { upload: 512, download: 0, total: 0, expire: null },
        }),
      ).traffic?.summary,
    ).toBe(`512 B used (${messages.en.trafficNone})`);
    expect(
      previewProfile(
        'zh',
        done({
          body: 'mode: rule\n',
          traffic: { upload: 512, download: 0, total: 0, expire: null },
        }),
      ).traffic?.summary,
    ).toBe(`已用 512 字节（${messages.zh.trafficNone}）`);
    expect(
      previewProfile(
        'en',
        done({
          body: 'mode: rule\n',
          traffic: { upload: 1536, download: 0, total: 0, expire: null },
        }),
      ).traffic?.summary,
    ).toBe(`1.50 KiB used (${messages.en.trafficNone})`);
    expect(
      previewProfile(
        'en',
        done({
          body: 'mode: rule\n',
          traffic: { upload: 10 * 1024 * 1024, download: 0, total: 0, expire: null },
        }),
      ).traffic?.summary,
    ).toBe(`10.0 MiB used (${messages.en.trafficNone})`);
  });

  it('reads traffic from the GET record on ok', () => {
    const profile = previewProfile(
      'en',
      done({
        body: 'mode: rule\n',
        traffic: {
          upload: 1024,
          download: 1024,
          total: 10 * 1024 * 1024,
          expire: null,
        },
      }),
    );
    expect(profile.error).toBeNull();
    expect(profile.traffic?.summary).toBe('2.00 KiB used of 10.0 MiB');
    expect(profile.traffic?.expire).toBeUndefined();
  });

  it('nests a dated expire under traffic', () => {
    const profile = previewProfile(
      'en',
      done({
        body: 'mode: rule\n',
        traffic: {
          upload: 1,
          download: 2,
          total: 3,
          expire: 1_893_456_000,
        },
      }),
    );
    expect(profile.error).toBeNull();
    expect(profile.traffic?.expire).toMatch(/^Expires /);
  });

  it('omits a date when Conversion re-emits expire=0', () => {
    const profile = previewProfile(
      'en',
      done({
        body: 'mode: rule\n',
        traffic: {
          upload: 1,
          download: 2,
          total: 3,
          expire: 0,
        },
      }),
    );
    expect(profile.error).toBeNull();
    expect(profile.traffic?.summary).toBe('3 B used of 3 B');
    expect(profile.traffic?.expire).toBeUndefined();
  });

  it('omits traffic when the GET has no subscription-userinfo', () => {
    const profile = previewProfile('en', done({ body: 'mode: rule\n' }));
    expect(profile.error).toBeNull();
    expect(profile.traffic).toBeUndefined();
  });

  it('keeps skip counts on the 400 that Conversion attaches them to', () => {
    const profile = previewProfile(
      'en',
      done({
        body: 'No nodes were found!',
        httpStatus: 400,
        kind: { kind: 'known-error', body: 'No nodes were found!' },
        skipped: { parse: 0, capability: 1, name: 0 },
      }),
    );
    expect(profile.error).toEqual({
      heading: 'No nodes were found',
      wire: 'No nodes were found!',
    });
    expect(profile.skipped).toBe('Skipped 1 node: 1 this client cannot import.');
    expect(profile.traffic).toBeUndefined();
  });

  it('keeps an HTTP error heading without a known-error wire body', () => {
    const profile = previewProfile(
      'en',
      done({
        body: 'upstream failed',
        httpStatus: 502,
        kind: { kind: 'http' },
      }),
    );
    expect(profile.error).toEqual({
      heading: `${messages.en.status} 502`,
      wire: null,
    });
    expect(profile.skipped).toBeUndefined();
  });

  it('localizes a known-error GET that never converted', () => {
    const profile = previewProfile(
      'zh',
      done({
        body: 'Bad Gateway',
        httpStatus: 502,
        kind: { kind: 'known-error', body: 'Bad Gateway' },
      }),
    );
    expect(profile.error).toEqual({
      heading: '网关错误',
      wire: 'Bad Gateway',
    });
  });

  it('phrases skip and omitted counts on ok', () => {
    const profile = previewProfile(
      'en',
      done({
        body: 'mode: rule\n',
        skipped: { parse: 1, capability: 0, name: 0 },
        omitted: { omittedUrlRegex: 3 },
      }),
    );
    expect(profile.error).toBeNull();
    expect(profile.skipped).toBe('Skipped 1 node: 1 could not be read.');
    expect(profile.omitted).toBe('Omitted 3 URL-REGEX rules (this client cannot use them).');
  });

  it('lists only the non-zero skip buckets in zh and en', () => {
    expect(
      previewProfile(
        'en',
        done({
          body: 'mode: rule\n',
          skipped: { parse: 1, capability: 4, name: 0 },
        }),
      ).skipped,
    ).toBe('Skipped 5 nodes: 1 could not be read, 4 this client cannot import.');
    expect(
      previewProfile(
        'en',
        done({
          body: 'mode: rule\n',
          skipped: { parse: 0, capability: 1, name: 0 },
        }),
      ).skipped,
    ).toBe('Skipped 1 node: 1 this client cannot import.');
    expect(
      previewProfile(
        'zh',
        done({
          body: 'mode: rule\n',
          skipped: { parse: 1, capability: 4, name: 0 },
        }),
      ).skipped,
    ).toBe('跳过 5 个节点：1 个读不出来，4 个这个客户端导不进去。');
  });

  it('names the omitted URL-REGEX count in zh and en', () => {
    expect(
      previewProfile(
        'en',
        done({
          body: 'mode: rule\n',
          omitted: { omittedUrlRegex: 3 },
        }),
      ).omitted,
    ).toBe('Omitted 3 URL-REGEX rules (this client cannot use them).');
    expect(
      previewProfile(
        'zh',
        done({
          body: 'mode: rule\n',
          omitted: { omittedUrlRegex: 3 },
        }),
      ).omitted,
    ).toBe('省略 3 条 URL-REGEX 规则（这个客户端不支持）。');
  });
});
