import { describe, expect, it } from 'vitest';

import { ids } from '../../fixtures/data.ts';
import { newFixtureState, respond, SESSION_COOKIE } from '../../fixtures/server.ts';
import {
  baselineRequest,
  bodyBytes,
  checkBaseline,
  checkFileSize,
  checkRepo,
  digestsThatFit,
  MAX_BODY_BYTES,
  MAX_FILE_BYTES,
  readExport,
} from './baseline';

const digest = (n: number) => n.toString(16).padStart(64, '0');
const EDR = '01M5C5QEHHNXJ3D7X2ZCMGXQT7';
const exported = (over: Record<string, unknown> = {}) => JSON.stringify({ baseline_export_version: 1, decision_id: EDR, fingerprints: [digest(1), digest(2)], ...over });

/** What the fixtures server answers to a baseline for this repository and digests, with the terms recorded. */
function serverSays(repo: string, fingerprints: string[]): number {
  const state = newFixtureState();
  const cookie = `${SESSION_COOKIE}=1`;
  const send = (url: string, body: unknown) =>
    respond({ method: 'POST', url, cookie, contentType: 'application/json', body: JSON.stringify(body) }, new Date('2026-11-07T12:00:00Z'), state);
  send(`/v1/decisions/${ids.useTls}/grandfather-period`, { valid_from: '2026-11-07T12:00:00Z' });
  return send(`/v1/decisions/${ids.useTls}/baselines`, { repo, fingerprints }).status;
}

describe('the file of ipso baseline export', () => {
  it('reads the export and keeps the decision and the digests', () => {
    expect(readExport(exported())).toEqual({ ok: true, value: { decisionId: EDR, fingerprints: [digest(1), digest(2)] } });
  });

  it('refuses a file that is not that export, and says why', () => {
    const refused = (text: string) => {
      const result = readExport(text);
      expect(result.ok, text.slice(0, 60)).toBe(false);
      return result.ok ? '' : result.error;
    };
    expect(refused('nope')).toMatch(/not JSON/);
    expect(refused('[]')).toMatch(/holds baseline_export_version/);
    expect(refused('null')).toMatch(/holds baseline_export_version/);
    expect(refused(JSON.stringify({ decision_id: EDR, fingerprints: [digest(1)] }))).toMatch(/holds baseline_export_version/);
    expect(refused(exported({ salt: 'a'.repeat(64) }))).toMatch(/and nothing else/);
    expect(refused(exported({ baseline_export_version: 2 }))).toMatch(/another version than 1/);
    expect(refused(exported({ baseline_export_version: '1' }))).toMatch(/another version than 1/);
    expect(refused(exported({ decision_id: '' }))).toMatch(/names no decision/);
    expect(refused(exported({ decision_id: 7 }))).toMatch(/names no decision/);
    expect(refused(exported({ fingerprints: [] }))).toMatch(/nothing to record/);
    expect(refused(exported({ fingerprints: 'abc' }))).toMatch(/nothing to record/);
    expect(refused(exported({ fingerprints: [digest(10).toUpperCase()] }))).toMatch(/64 lowercase hexadecimal/);
    expect(refused(exported({ fingerprints: [digest(1).slice(1)] }))).toMatch(/64 lowercase hexadecimal/);
    expect(refused(exported({ fingerprints: [1] }))).toMatch(/64 lowercase hexadecimal/);
    expect(refused(exported({ fingerprints: [digest(1), digest(1)] }))).toMatch(/appears twice/);
  });

  it('reads a file up to 8 MiB and no more', () => {
    expect(checkFileSize(MAX_FILE_BYTES)).toBeNull();
    expect(checkFileSize(MAX_FILE_BYTES + 1)).toMatch(/larger than 8 MiB/);
  });

  it('fits the export of the 100,000 digests the registry allows', () => {
    // One digest of an export is the digest, two quotes, a comma, a newline and four spaces of indent.
    expect(100000 * (64 + 2 + 1 + 1 + 4)).toBeLessThan(MAX_FILE_BYTES);
  });
});

describe('the repository of a baseline', () => {
  const good = ['acme/payments', 'a/b', 'acme/a.b_c-d', 'acme/team/api', `${'a'.repeat(63)}/${'b'.repeat(100)}`];
  const bad = ['', 'acme', 'Acme/payments', 'acme/Payments', 'acme//api', 'acme/api/', '/acme/api', 'acme/.', 'acme/..', './api', 'acme/../api', '-acme/api', 'acme/a b', 'acme/api?x', `${'a'.repeat(64)}/b`, `acme/${'b'.repeat(101)}`];

  it('is a lowercase owner/name as the registry reads a subject', () => {
    for (const repo of good) expect(checkRepo(repo), repo).toBeNull();
    for (const repo of bad) expect(checkRepo(repo), repo).toMatch(/lowercase owner\/name/);
  });

  it('agrees with the fixtures server, which keeps the rule of the real one', () => {
    for (const repo of [...good, ...bad]) {
      expect(serverSays(repo, [digest(1)]) === 201, repo).toBe(checkRepo(repo) === null);
    }
  });
});

describe('the size of the request', () => {
  it('counts the body exactly', () => {
    for (const count of [0, 1, 2, 10]) {
      const text = JSON.stringify({ repo: 'acme/api', fingerprints: Array.from({ length: count }, (_, i) => digest(i)) });
      expect(bodyBytes('acme/api', count), `${count}`).toBe(text.length);
    }
  });

  it('takes about 15,600 digests under 1 MiB, and one more is over', () => {
    const fit = digestsThatFit('acme/api');
    expect(fit).toBeGreaterThan(15500);
    expect(fit).toBeLessThan(15700);
    expect(bodyBytes('acme/api', fit)).toBeLessThanOrEqual(MAX_BODY_BYTES);
    expect(bodyBytes('acme/api', fit + 1)).toBeGreaterThan(MAX_BODY_BYTES);
    // The real body has the length that was counted.
    const body = JSON.stringify(baselineRequest('acme/api', Array.from({ length: fit }, (_, i) => digest(i))));
    expect(body.length).toBe(bodyBytes('acme/api', fit));
  });

  it('is the cap of the fixtures server: the last digest that fits is recorded, the next one is a 413', () => {
    const fit = digestsThatFit('acme/api');
    const digests = (n: number) => Array.from({ length: n }, (_, i) => digest(i));
    expect(serverSays('acme/api', digests(fit))).toBe(201);
    expect(serverSays('acme/api', digests(fit + 1))).toBe(413);
  });

  it('takes fewer digests for a longer repository name', () => {
    expect(digestsThatFit(`${'a'.repeat(63)}/${'b'.repeat(100)}`)).toBeLessThanOrEqual(digestsThatFit('a/b'));
  });
});

describe('the baseline form', () => {
  const file = { decisionId: EDR, fingerprints: [digest(1), digest(2)] };
  const form = { decisionId: ids.useTls, edrId: EDR, repo: 'acme/api', file };

  it('has no error for a decision, a repository and the file made for it', () => {
    expect(checkBaseline(form)).toEqual({});
  });

  it('asks for each missing piece', () => {
    expect(checkBaseline({ ...form, decisionId: '' }).decisionId).toBe('Pick the decision.');
    expect(checkBaseline({ ...form, repo: 'Acme' }).repo).toMatch(/lowercase owner\/name/);
    expect(checkBaseline({ ...form, file: null }).file).toMatch(/Choose the file/);
  });

  it('refuses a decision that is not in force or has no EDR id, since no file can name it', () => {
    expect(checkBaseline({ ...form, edrId: null }).decisionId).toMatch(/no EDR id/);
  });

  it('refuses a file made for another decision, and names both', () => {
    const other = '01M5C5QEHHNXJ3D7X2ZCMGXQT8';
    const message = checkBaseline({ ...form, file: { ...file, decisionId: other } }).file ?? '';
    expect(message).toContain(other);
    expect(message).toContain(EDR);
  });

  it('shortens and cleans an id from a file before it shows it', () => {
    const message = checkBaseline({ ...form, file: { ...file, decisionId: `x\u001b[31m${'y'.repeat(200)}` } }).file ?? '';
    expect(message).not.toContain('\u001b');
    expect(message.length).toBeLessThan(200);
    expect(message).toContain('...');
  });

  it('refuses a baseline over 1 MiB with the count and the limit, before anything is sent', () => {
    const fit = digestsThatFit('acme/api');
    const large = { ...file, fingerprints: Array.from({ length: fit + 1 }, (_, i) => digest(i)) };
    const message = checkBaseline({ ...form, file: large }).file ?? '';
    expect(message).toContain((fit + 1).toLocaleString('en-US'));
    expect(message).toContain(fit.toLocaleString('en-US'));
    expect(message).toMatch(/1 MiB/);
    expect(message).toMatch(/Nothing is sent/);
    expect(checkBaseline({ ...form, file: { ...file, fingerprints: large.fingerprints.slice(0, fit) } })).toEqual({});
  });

  it('builds a request with the repository and the digests and nothing else', () => {
    const request = baselineRequest('acme/api', file.fingerprints);
    expect(Object.keys(request)).toEqual(['repo', 'fingerprints']);
    expect(request.fingerprints).toEqual(file.fingerprints);
    expect(request.fingerprints).not.toBe(file.fingerprints);
    expect(JSON.stringify(request)).not.toMatch(/tenant|principal|approver|salt|decision/i);
  });
});
