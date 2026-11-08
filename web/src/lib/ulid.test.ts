import { describe, expect, it } from 'vitest';

import { newUlid } from './ulid';

const zeros = (bytes: Uint8Array) => bytes.fill(0);
const ones = (bytes: Uint8Array) => bytes.fill(0xff);
// The pattern of the id in the EDR schema, draft 0.2.
const EDR_ID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

describe('newUlid', () => {
  it('is 26 characters of Crockford base32 with the time first', () => {
    expect(newUlid(0, zeros)).toBe('0'.repeat(26));
    expect(newUlid(0, ones)).toBe(`${'0'.repeat(10)}${'Z'.repeat(16)}`);
    expect(newUlid(2 ** 48 - 1, zeros)).toBe(`7${'Z'.repeat(9)}${'0'.repeat(16)}`);
    expect(newUlid(1, zeros)).toBe(`${'0'.repeat(9)}1${'0'.repeat(16)}`);
    expect(newUlid(32, zeros)).toBe(`${'0'.repeat(8)}10${'0'.repeat(16)}`);
  });

  it('matches the id of an EDR whatever the time and the random bytes are', () => {
    for (const time of [0, 1, 1_762_560_000_000, 2 ** 48 - 1]) {
      expect(newUlid(time, ones)).toMatch(EDR_ID);
      expect(newUlid(time)).toMatch(EDR_ID);
    }
  });

  it('sorts by the time it was made', () => {
    expect(newUlid(1_000, ones) < newUlid(2_000, zeros)).toBe(true);
  });

  it('reads the random bytes in order, five bits at a time', () => {
    const bytes = Uint8Array.from([0b00001000, 0b01000000, 0, 0, 0, 0, 0, 0, 0, 0]);
    // 00001 00001 00000 ... is "11" followed by zeros.
    expect(newUlid(0, (out) => out.set(bytes)).slice(10)).toBe(`11${'0'.repeat(14)}`);
  });

  it('draws different ids from the real random source', () => {
    expect(newUlid(5)).not.toBe(newUlid(5));
  });

  it('refuses a time that does not fit in 48 bits', () => {
    expect(() => newUlid(-1)).toThrow(RangeError);
    expect(() => newUlid(2 ** 48)).toThrow(RangeError);
    expect(() => newUlid(Number.NaN)).toThrow(RangeError);
  });
});
