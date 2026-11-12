import { describe, expect, it } from 'vitest';

import { fieldToTime, formatBytes, formatDate, formatTime, nowAsTime, nowForField, shortId, timeToField } from './format';

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

describe('formatBytes', () => {
  it('says a size in the unit a person reads', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(812)).toBe('812 B');
    expect(formatBytes(1024)).toBe('1.00 KiB');
    expect(formatBytes(3.4 * 1024 * 1024)).toBe('3.40 MiB');
    expect(formatBytes(12.5 * 1024 * 1024)).toBe('12.5 MiB');
    expect(formatBytes(1024 ** 3)).toBe('1.00 GiB');
  });
});
