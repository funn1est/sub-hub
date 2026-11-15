import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { messages, t } from '@/lib/i18n.ts';

import { VersionBadge } from './workshop-section.tsx';

describe('VersionBadge', () => {
  it('announces the visible /version body when the probe succeeds', () => {
    const body = 'sub-hub v0.1.0 backend';
    const html = renderToStaticMarkup(
      createElement(VersionBadge, { state: { status: 'ok', body }, copy: t('zh') }),
    );
    expect(html).toContain(body);
    expect(html).not.toContain('aria-label');
    expect(html).not.toContain('Conversion Service');
  });
});

describe('versionOk copy', () => {
  it('is gone from both locales', () => {
    expect(Object.keys(messages.en)).not.toContain('versionOk');
    expect(Object.keys(messages.zh)).not.toContain('versionOk');
  });
});
