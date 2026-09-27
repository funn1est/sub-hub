import { describe, expect, it } from 'vitest';

import { messages } from './i18n.ts';
import { configChoiceGroups, configChoiceLabel, configChoiceMatches } from './workshop-config.ts';

describe('configChoiceLabel', () => {
  it('returns the visible string, not the search haystack', () => {
    const groups = configChoiceGroups(messages.en);
    const none = groups[0]?.items[0];
    const online = groups[1]?.items[0];
    if (none === undefined || online === undefined) {
      throw new Error('expected none and Online choices');
    }

    expect(none.search).toBe('Nodes only (PROXY/AUTO) PROXY AUTO');
    expect(configChoiceLabel(none)).toBe('Nodes only (PROXY/AUTO)');
    expect(configChoiceLabel(none)).not.toBe(none.search);

    expect(online.id).toBe('ACL4SSR_Online.ini');
    expect(online.search).toBe('Ads and China split ACL4SSR_Online ACL4SSR_Online.ini');
    expect(configChoiceLabel(online)).toBe('Ads and China split · ACL4SSR_Online');
    expect(configChoiceLabel(online).includes('.ini')).toBe(false);
  });
});

describe('configChoiceMatches', () => {
  it('matches haystack tokens that are absent from the visible label', () => {
    const groups = configChoiceGroups(messages.en);
    const none = groups[0]?.items[0];
    const online = groups[1]?.items[0];
    const custom = groups[5]?.items[0];
    if (none === undefined || online === undefined || custom === undefined) {
      throw new Error('expected none, Online, and custom choices');
    }

    expect(configChoiceMatches(none, 'PROXY AUTO')).toBe(true);
    expect(configChoiceLabel(none).includes('PROXY AUTO')).toBe(false);
    expect(configChoiceMatches(online, 'ACL4SSR_Online.ini')).toBe(true);
    expect(configChoiceMatches(online, '.ini')).toBe(true);
    expect(configChoiceLabel(online).includes('.ini')).toBe(false);
    expect(configChoiceMatches(online, 'no-such-token')).toBe(false);
    expect(configChoiceMatches(online, '')).toBe(true);
    expect(configChoiceMatches(custom, 'Custom URL')).toBe(true);
  });
});
