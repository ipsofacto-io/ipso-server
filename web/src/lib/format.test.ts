import { describe, expect, it } from 'vitest';

import { fieldToTime, formatDate, formatTime, nowAsTime, nowForField, shortId, timeToField } from './format';

describe('format', () => {
  it('writes a time in UTC to the minute', () => {
    expect(formatTime('2026-11-07T14:30:59+02:00')).toBe('2026-11-07 12:30 UTC');
    expect(formatTime('not a time')).toBe('not a time');
  });

  it('keeps an EDR date as it is', () => {
    expect(formatDate('2026-12-01')).toBe('2026-12-01');
    expect(formatDate('2026-12-01T10:00:00Z')).toBe('2026-12-01 10:00 UTC');
  });

  it('reads a datetime-local value as UTC and writes it back', () => {
    expect(fieldToTime('2026-11-07T14:30')).toBe('2026-11-07T14:30:00Z');
    expect(fieldToTime('2026-11-07T14:30:00Z')).toBe('2026-11-07T14:30:00Z');
    expect(timeToField('2026-11-07T14:30:00Z')).toBe('2026-11-07T14:30');
    expect(timeToField(null)).toBe('');
    expect(timeToField('nope')).toBe('');
    expect(nowForField(new Date('2026-11-07T09:05:30Z'))).toBe('2026-11-07T09:06');
    expect(nowForField(new Date('2026-11-07T09:05:00Z'))).toBe('2026-11-07T09:05');
    expect(nowAsTime(new Date('2026-11-07T09:05:30.250Z'))).toBe('2026-11-07T09:05:30.250Z');
  });

  it('shortens an id', () => {
    expect(shortId('0194f2a0-0000-7000-8000-000000000101')).toBe('0194f2a0');
    expect(shortId('abc')).toBe('abc');
  });
});
