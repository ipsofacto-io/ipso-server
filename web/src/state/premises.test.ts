import { describe, expect, it } from 'vitest';

import { checkHost, clearance, hostRequest, HOST_MAX, premiseValue } from './premises';

describe('checkHost', () => {
  it('trims and lowercases a host the way the server reads it', () => {
    expect(checkHost('  Status.Example.COM ')).toEqual({ ok: true, host: 'status.example.com' });
    expect(checkHost('a.b-c.example.com')).toEqual({ ok: true, host: 'a.b-c.example.com' });
    expect(checkHost('xn--bcher-kva.example')).toEqual({ ok: true, host: 'xn--bcher-kva.example' });
  });

  it('asks for a host when the field is empty', () => {
    expect(checkHost('   ')).toMatchObject({ ok: false, error: expect.stringContaining('Give the host name') });
  });

  it('refuses an address, whether it is v4 or only digits and dots', () => {
    for (const value of ['10.0.0.1', '127.0.0.1', '1.2', '300.300.300.300']) {
      expect(checkHost(value), value).toMatchObject({ ok: false, error: expect.stringContaining('address') });
    }
  });

  it('refuses a scheme, a port, a path, a space, a name with no dot and a name that is not ASCII', () => {
    for (const value of ['https://status.example.com', 'status.example.com:443', 'status.example.com/health', 'status example.com', 'localhost', 'bücher.example', '.example.com', 'example..com', '-a.example.com', 'a-.example.com']) {
      expect(checkHost(value), value).toMatchObject({ ok: false, error: expect.stringContaining('DNS name') });
    }
  });

  it('holds a host to 253 characters and a label to 63', () => {
    const label = 'a'.repeat(63);
    const long = [label, label, label, 'a'.repeat(61)].join('.');
    expect(long.length).toBe(HOST_MAX);
    expect(checkHost(long).ok).toBe(true);
    expect(checkHost(`${long}a`)).toMatchObject({ ok: false, error: expect.stringContaining('253') });
    expect(checkHost(`${'a'.repeat(64)}.example.com`).ok).toBe(false);
  });
});

describe('the requests of the premises page', () => {
  it('names a host and a flag and nothing else', () => {
    expect(hostRequest('status.example.com', true)).toEqual({ host: 'status.example.com', allowed: true });
    expect(hostRequest('status.example.com', false)).toEqual({ host: 'status.example.com', allowed: false });
  });

  it('sends an empty object for a clearance, which names no approver', () => {
    expect(clearance()).toEqual({});
  });
});

describe('premiseValue', () => {
  it('shows a stored value as JSON text, so a string and a boolean differ', () => {
    expect(premiseValue('false')).toBe('"false"');
    expect(premiseValue(false)).toBe('false');
    expect(premiseValue(null)).toBe('null');
    expect(premiseValue({ min: '1.3' })).toBe('{"min":"1.3"}');
    expect(premiseValue('<script>alert(1)</script>')).toBe('"<script>alert(1)</script>"');
  });

  it('answers null for a value that is not JSON', () => {
    expect(premiseValue(undefined)).toBe('null');
  });
});
