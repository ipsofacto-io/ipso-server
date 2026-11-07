import { describe, expect, it } from 'vitest';

import { safeHttpsUrl } from './url';

describe('safeHttpsUrl', () => {
  it('keeps an https URL', () => {
    expect(safeHttpsUrl('https://github.com/acme/payments/pull/70')).toBe('https://github.com/acme/payments/pull/70');
  });

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'http://example.com',
    'ftp://example.com',
    '//example.com',
    '/relative',
    'https://user:pass@example.com',
    '',
    'not a url',
  ])('refuses %s', (value) => {
    expect(safeHttpsUrl(value)).toBeNull();
  });

  it('refuses a value that is not text, or is very long', () => {
    expect(safeHttpsUrl(undefined)).toBeNull();
    expect(safeHttpsUrl({ href: 'https://example.com' })).toBeNull();
    expect(safeHttpsUrl(`https://example.com/${'a'.repeat(3000)}`)).toBeNull();
  });
});
