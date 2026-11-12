import { describe, expect, it } from 'vitest';

import type { Export } from '../api/types';
import { canDownload, checkRecipient, isUnderWay } from './export';

const RECIPIENT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';

const held = (state: Export['state'], expires = '2026-11-08T00:00:00Z'): Export => ({
  id: '0194f2a0-0000-7000-8000-000000000001',
  state,
  requested_by: '0194f2a0-0000-7000-8000-0000000000a1',
  created_at: '2026-11-07T00:00:00Z',
  finished_at: state === 'ready' || state === 'failed' ? '2026-11-07T00:01:00Z' : null,
  expires_at: expires,
  bytes: state === 'ready' ? 10 : null,
  sha256: state === 'ready' ? 'a'.repeat(64) : null,
});

describe('the key of an export', () => {
  it('trims a public key and leaves every other check to the server', () => {
    expect(checkRecipient(`  ${RECIPIENT}\t`)).toEqual({ ok: true, recipient: RECIPIENT });
    expect(checkRecipient('not a key at all')).toEqual({ ok: true, recipient: 'not a key at all' });
  });

  it('asks for a key when there is none', () => {
    expect(checkRecipient('   ')).toMatchObject({ ok: false, privateKey: false });
  });

  it('refuses a private key, native or post-quantum, in any case', () => {
    for (const secret of ['AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQ', 'AGE-SECRET-KEY-PQ-1QQQQQQQQ', ' age-secret-key-1qqqq']) {
      expect(checkRecipient(secret)).toMatchObject({ ok: false, privateKey: true });
    }
  });
});

describe('the state of an export', () => {
  it('is under way while pending or running', () => {
    expect(isUnderWay(held('pending'))).toBe(true);
    expect(isUnderWay(held('running'))).toBe(true);
    expect(isUnderWay(held('ready'))).toBe(false);
    expect(isUnderWay(held('failed'))).toBe(false);
    expect(isUnderWay(null)).toBe(false);
  });

  it('can be downloaded only when ready and not expired', () => {
    const now = Date.parse('2026-11-07T12:00:00Z');
    expect(canDownload(held('ready'), now)).toBe(true);
    expect(canDownload(held('ready', '2026-11-07T11:59:59Z'), now)).toBe(false);
    for (const state of ['pending', 'running', 'failed'] as const) expect(canDownload(held(state), now)).toBe(false);
  });
});
