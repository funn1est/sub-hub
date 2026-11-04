import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Combobox } from '@base-ui/react';

import { messages } from './i18n.ts';
import { configChoiceGroups, configChoiceLabel, type ConfigChoice } from './workshop-config.ts';

function choice(id: ConfigChoice['id']): ConfigChoice {
  const item = configChoiceGroups(messages.en)
    .flatMap((group) => group.items)
    .find((entry) => entry.id === id);
  if (item === undefined) {
    throw new Error(`missing config choice ${id}`);
  }
  return item;
}

function collatorMatches(
  item: ConfigChoice,
  query: string,
  itemToString: (item: ConfigChoice) => string,
): boolean {
  function Probe() {
    const { contains } = Combobox.useFilter();
    return createElement('span', null, String(contains(item, query, itemToString)));
  }
  return renderToStaticMarkup(createElement(Probe)).includes('>true<');
}

describe('configChoiceLabel', () => {
  it('returns the visible string, not the search haystack', () => {
    const none = choice('none');
    const online = choice('ACL4SSR_Online.ini');

    expect(none.search).toBe('Nodes only (PROXY/AUTO) PROXY AUTO');
    expect(configChoiceLabel(none)).toBe('Nodes only (PROXY/AUTO)');
    expect(configChoiceLabel(none).includes('PROXY AUTO')).toBe(false);

    expect(online.search).toBe('Ads and China split ACL4SSR_Online ACL4SSR_Online.ini');
    expect(configChoiceLabel(online)).toBe('Ads and China split · ACL4SSR_Online');
    expect(configChoiceLabel(online).includes('.ini')).toBe(false);
  });
});

describe('combobox collator on config search', () => {
  it('matches haystack tokens that are absent from the visible label', () => {
    const none = choice('none');
    const online = choice('ACL4SSR_Online.ini');

    expect(collatorMatches(none, 'PROXY AUTO', (item) => item.search)).toBe(true);
    expect(collatorMatches(online, '.ini', (item) => item.search)).toBe(true);
    expect(collatorMatches(online, 'ACL4SSR_Online.ini', (item) => item.search)).toBe(true);
    expect(collatorMatches(online, 'online ini', (item) => item.search)).toBe(true);
    expect(collatorMatches(online, 'ACL4SSR.Online.ini', (item) => item.search)).toBe(true);
    expect(collatorMatches(online, '.ini', configChoiceLabel)).toBe(false);
    expect(collatorMatches(online, 'ACL4SSR_Online.ini', configChoiceLabel)).toBe(false);
    expect(collatorMatches(online, 'online ini', configChoiceLabel)).toBe(false);
    expect(collatorMatches(online, 'no-such-token', (item) => item.search)).toBe(false);
    expect(collatorMatches(online, '', (item) => item.search)).toBe(true);
  });
});
