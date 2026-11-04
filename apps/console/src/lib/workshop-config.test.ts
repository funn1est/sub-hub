import { describe, expect, it } from 'vitest';

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
