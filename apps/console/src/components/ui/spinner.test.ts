import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { t } from '@/lib/i18n.ts';

import { PreviewCard } from '../workshop-preview.tsx';
import { VersionBadge } from '../workshop-section.tsx';
import { Spinner } from './spinner.tsx';

describe('Spinner', () => {
  it('stays out of the accessibility tree when adjacent copy names the state', () => {
    const html = renderToStaticMarkup(createElement(Spinner, { decorative: true }));
    expect(html).toContain('aria-hidden="true"');
    expect(html).not.toContain('Loading');
    expect(html).not.toContain('role="status"');
    expect(html).not.toContain('aria-label');
  });

  it('announces only the localized label when it is the name of the state', () => {
    const html = renderToStaticMarkup(createElement(Spinner, { label: t('zh').versionChecking }));
    expect(html).toContain('aria-label="正在检查 /version…"');
    expect(html).toContain('role="status"');
    expect(html).not.toContain('Loading');
  });
});

describe('VersionBadge', () => {
  it('does not announce English Loading next to zh versionChecking', () => {
    const html = renderToStaticMarkup(
      createElement(VersionBadge, { state: { status: 'checking' }, copy: t('zh') }),
    );
    expect(html).toContain('正在检查 /version…');
    expect(html).toContain('aria-hidden="true"');
    expect(html).not.toContain('Loading');
    expect(html).not.toContain('aria-label="Loading"');
  });
});

describe('PreviewCard', () => {
  it('does not announce English Loading next to zh previewing', () => {
    const html = renderToStaticMarkup(
      createElement(PreviewCard, {
        locale: 'zh',
        preview: { status: 'loading' },
        copy: t('zh'),
        onDownload() {},
      }),
    );
    expect(html).toContain('正在 Preview…');
    expect(html).toContain('aria-hidden="true"');
    expect(html).not.toContain('Loading');
    expect(html).not.toContain('aria-label="Loading"');
  });
});
