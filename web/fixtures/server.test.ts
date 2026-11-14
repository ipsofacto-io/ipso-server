import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { ids, scopes } from './data.ts';
import { EXPORT_BYTES, EXPORT_SHA256, newFixtureState, respond, SESSION_COOKIE, type FixtureRequest } from './server.ts';

const NOW = new Date('2026-11-07T12:00:00Z');
const cookie = `${SESSION_COOKIE}=1`;

function post(path: string, body: unknown, state = newFixtureState(), extra: Partial<FixtureRequest> = {}) {
  const request: FixtureRequest = { method: 'POST', url: path, cookie, contentType: 'application/json', body: JSON.stringify(body), ...extra };
  return { reply: respond(request, NOW, state), state };
}

const PROPOSAL = '0194f2a0-0000-7000-8000-000000000302';
const approval = {
  outcome: 'approved',
  decision: { body: { slug: 'use-vault', title: 'Use the vault' }, scope_refs: [ids.repo], valid_from: '2026-11-07T00:00:00Z' },
};
const waiver = {
  decision_id: ids.useTls,
  scope_id: ids.prod,
  reason: 'under way',
  ticket_ref: 'SEC-1',
  valid_from: '2026-11-07T12:00:00Z',
  expires_at: '2026-12-07T12:00:00Z',
};

describe('the write routes of the fixtures server', () => {
  it('needs a session', () => {
    expect(post(`/v1/proposals/${PROPOSAL}/approval`, approval, newFixtureState(), { cookie: '' }).reply.status).toBe(401);
  });

  it('wants a JSON content type and a body under 1 MiB', () => {
    expect(post('/v1/waivers', waiver, newFixtureState(), { contentType: 'text/plain' }).reply.status).toBe(415);
    expect(post('/v1/waivers', waiver, newFixtureState(), { body: 'x'.repeat((1 << 20) + 1) }).reply.status).toBe(413);
    expect(post('/v1/waivers', waiver, newFixtureState(), { body: '{not json' }).reply.status).toBe(400);
  });

  it('refuses a key the route does not list, such as an approver', () => {
    expect(post('/v1/waivers', { ...waiver, approver: 'someone' }).reply.status).toBe(400);
    expect(post('/v1/waivers', { ...waiver, tenant: 'a' }).reply.status).toBe(400);
    expect(post(`/v1/proposals/${PROPOSAL}/approval`, { ...approval, approver: 'x' }).reply.status).toBe(400);
  });

  it('holds a waiver to 90 days and 404s an unknown decision or scope', () => {
    expect(post('/v1/waivers', { ...waiver, expires_at: '2027-02-05T12:00:00Z' }).reply.status).toBe(201);
    expect(post('/v1/waivers', { ...waiver, expires_at: '2027-02-05T12:00:01Z' }).reply.status).toBe(400);
    expect(post('/v1/waivers', { ...waiver, expires_at: waiver.valid_from }).reply.status).toBe(400);
    expect(post('/v1/waivers', { ...waiver, decision_id: '0194f2a0-0000-7000-8000-0000000009ff' }).reply.status).toBe(404);
  });

  it('wants a decision with an approval, none with a rejection, and answers a draft once', () => {
    expect(post(`/v1/proposals/${PROPOSAL}/approval`, { outcome: 'approved' }).reply.status).toBe(400);
    expect(post(`/v1/proposals/${PROPOSAL}/approval`, { outcome: 'rejected', decision: approval.decision }).reply.status).toBe(400);
    expect(post(`/v1/proposals/${PROPOSAL}/approval`, { ...approval, decision: { ...approval.decision, scope_refs: ['0194f2a0-0000-7000-8000-0000000009ff'] } }).reply.status).toBe(400);
    expect(post('/v1/proposals/0194f2a0-0000-7000-8000-0000000009ff/approval', { outcome: 'rejected' }).reply.status).toBe(404);

    const first = post(`/v1/proposals/${PROPOSAL}/approval`, approval);
    expect(first.reply.status).toBe(201);
    expect(first.state.answered.has(PROPOSAL)).toBe(true);
    expect(post(`/v1/proposals/${PROPOSAL}/approval`, { outcome: 'rejected' }, first.state).reply.status).toBe(409);
    expect(scopes.some((scope) => scope.id === ids.repo)).toBe(true);
  });

  it('supersedes a decision once, and gives a decision one set of grandfather terms', () => {
    const body = { from_decision: ids.pinImages, to_decision: ids.useTls, effective_at: '2026-11-07T12:00:00Z' };
    expect(post('/v1/supersessions', { ...body, to_decision: ids.pinImages }).reply.status).toBe(400);
    expect(post('/v1/supersessions', { ...body, from_decision: ids.legacyFtp }).reply.status).toBe(409);
    const first = post('/v1/supersessions', body);
    expect(first.reply.status).toBe(201);
    expect(post('/v1/supersessions', body, first.state).reply.status).toBe(409);

    const path = `/v1/decisions/${ids.useTls}/grandfather-period`;
    expect(post(path, { valid_from: body.effective_at, valid_until: body.effective_at }).reply.status).toBe(400);
    const terms = post(path, { valid_from: body.effective_at }, first.state);
    expect(terms.reply).toMatchObject({ status: 201, body: { valid_until: null } });
    expect(post(path, { valid_from: body.effective_at }, terms.state).reply.status).toBe(409);
  });
});

describe('the baseline of a repository in the fixtures server', () => {
  const path = (decision: string = ids.useTls) => `/v1/decisions/${decision}/baselines`;
  const digest = (n: number) => n.toString(16).padStart(64, '0');
  const baseline = { repo: 'acme/api', fingerprints: [digest(1), digest(2)] };
  const withTerms = () => {
    const state = newFixtureState();
    post(`/v1/decisions/${ids.useTls}/grandfather-period`, { valid_from: '2026-11-07T12:00:00Z' }, state);
    return state;
  };

  it('needs the grandfather terms of the decision first', () => {
    expect(post(path(), baseline).reply.status).toBe(409);
    expect(post(path(), baseline, withTerms()).reply).toMatchObject({ status: 201, body: { decision_id: ids.useTls, repo: 'acme/api', fingerprint_count: 2 } });
  });

  it('records one baseline for each repository and answers a repeat with 409', () => {
    const state = withTerms();
    expect(post(path(), baseline, state).reply.status).toBe(201);
    expect(post(path(), baseline, state).reply.status).toBe(409);
    expect(post(path(), { ...baseline, repo: 'acme/web' }, state).reply.status).toBe(201);
  });

  it('refuses what the registry would refuse, and a key the route does not list', () => {
    const state = withTerms();
    for (const body of [
      { ...baseline, repo: 'Acme/api' },
      { ...baseline, repo: 'acme' },
      { ...baseline, repo: 'acme/../api' },
      { ...baseline, repo: 'acme/api/' },
      { ...baseline, fingerprints: [] },
      { ...baseline, fingerprints: [digest(1), digest(1)] },
      { ...baseline, fingerprints: [digest(10).toUpperCase()] },
      { ...baseline, fingerprints: [digest(1).slice(1)] },
      { ...baseline, fingerprints: [7] },
      { ...baseline, tenant: 'a' },
      { repo: baseline.repo },
    ]) {
      expect(post(path(), body, state).reply.status, JSON.stringify(body).slice(0, 80)).toBe(400);
    }
    expect(post(path('not-a-uuid'), baseline, state).reply.status).toBe(400);
  });

  it('answers 404 for a decision that does not exist, and stores nothing over 1 MiB', () => {
    const state = withTerms();
    expect(post(path('0194f2a0-0000-7000-8000-0000000009ff'), baseline, state).reply.status).toBe(404);
    const large = { repo: 'acme/api', fingerprints: Array.from({ length: 15700 }, (_, i) => digest(i)) };
    expect(JSON.stringify(large).length).toBeGreaterThan(1 << 20);
    expect(post(path(), large, state).reply.status).toBe(413);
    expect(post(path(), baseline, state).reply.status).toBe(201);
  });
});

describe('the answer to a drafted check in the fixtures server', () => {
  const CHECK = '0194f2a0-0000-7000-8000-000000000501';
  const path = (decision: string = ids.useTls, check: string = CHECK) => `/v1/decisions/${decision}/check-proposals/${check}/approval`;
  const queue = (state: ReturnType<typeof newFixtureState>) =>
    (respond({ method: 'GET', url: '/v1/check-proposals', cookie }, NOW, state).body as { check_proposals: { id: string }[] }).check_proposals;

  it('needs a session and a body with the outcome and nothing else', () => {
    expect(post(path(), { outcome: 'approved' }, newFixtureState(), { cookie: '' }).reply.status).toBe(401);
    expect(post(path(), {}).reply.status).toBe(400);
    expect(post(path(), { outcome: 'maybe' }).reply.status).toBe(400);
    expect(post(path(), { outcome: 'approved', approver: 'someone' }).reply.status).toBe(400);
    expect(post(path(), { outcome: 'approved', decision: approval.decision }).reply.status).toBe(400);
  });

  it('answers 404 for a check that is not under that decision, and for one that does not exist', () => {
    expect(post(path(ids.pinImages), { outcome: 'approved' }).reply.status).toBe(404);
    expect(post(path(ids.useTls, '0194f2a0-0000-7000-8000-0000000009ff'), { outcome: 'rejected' }).reply.status).toBe(404);
  });

  it('records one outcome, takes the check out of the queue, and answers a second time with 409', () => {
    const state = newFixtureState();
    expect(queue(state).map((item) => item.id)).toEqual([CHECK]);
    const first = post(path(), { outcome: 'approved' }, state);
    expect(first.reply).toMatchObject({ status: 201, body: { proposal_id: CHECK, outcome: 'approved' } });
    expect(queue(state)).toEqual([]);
    expect(post(path(), { outcome: 'rejected' }, state).reply.status).toBe(409);
    expect(post(path(), { outcome: 'approved' }, state).reply.status).toBe(409);
  });

  it('writes no decision and leaves the proposals alone', () => {
    const state = newFixtureState();
    post(path(), { outcome: 'rejected' }, state);
    expect(state.decisions).toEqual([]);
    expect(state.answered.has(PROPOSAL)).toBe(false);
  });
});

describe('the premise routes of the fixtures server', () => {
  const ADMIN_PORT = ids.adminPort;
  const clearancePath = (decision: string = ADMIN_PORT, premise = 'bastion-exists') => `/v1/decisions/${decision}/premises/${premise}/clearance`;
  const get = (path: string, state = newFixtureState(), signedIn = true) => respond({ method: 'GET', url: path, cookie: signedIn ? cookie : '' }, NOW, state);
  const reasons = (state: ReturnType<typeof newFixtureState>) => (get('/v1/premise-reasons', state).body as { premise_reasons: { id: string; premise_id: string }[] }).premise_reasons;
  const hosts = (state: ReturnType<typeof newFixtureState>) => (get('/v1/premise-hosts', state).body as { premise_hosts: { id: string; host: string; allowed: boolean }[] }).premise_hosts;

  it('needs a session and no query key but the paging', () => {
    expect(get('/v1/premise-reasons', newFixtureState(), false).status).toBe(401);
    expect(get('/v1/premise-hosts', newFixtureState(), false).status).toBe(401);
    expect(post(clearancePath(), {}, newFixtureState(), { cookie: '' }).reply.status).toBe(401);
    expect(post('/v1/premise-hosts', { host: 'a.example.com', allowed: true }, newFixtureState(), { cookie: '' }).reply.status).toBe(401);
    for (const path of ['/v1/premise-reasons', '/v1/premise-hosts']) {
      expect(get(`${path}?valid=2026-11-07T00:00:00Z`).status, path).toBe(400);
      expect(get(`${path}?known=2026-11-07T00:00:00Z`).status, path).toBe(400);
      expect(get(`${path}?limit=1&limit=2`).status, path).toBe(400);
      expect(get(`${path}?limit=1`).status, path).toBe(200);
    }
  });

  it('lists the open reasons from the highest id, and pages by id', () => {
    const state = newFixtureState();
    expect(reasons(state).map((reason) => reason.premise_id)).toEqual(['tls-min-version', 'bastion-exists']);
    const first = (get('/v1/premise-reasons?limit=1').body as { premise_reasons: { id: string }[] }).premise_reasons;
    expect(first).toHaveLength(1);
    const next = (get(`/v1/premise-reasons?limit=1&before=${first[0]?.id}`).body as { premise_reasons: { premise_id: string }[] }).premise_reasons;
    expect(next.map((reason) => reason.premise_id)).toEqual(['bastion-exists']);
  });

  it('lists the latest row of each host, a withdrawn host included', () => {
    expect(hosts(newFixtureState()).map(({ host, allowed }) => ({ host, allowed }))).toEqual([
      { host: 'legacy.example.com', allowed: false },
      { host: 'status.example.com', allowed: true },
    ]);
  });

  it('wants a clearance to be an empty object, under a decision and a premise id that are well formed', () => {
    expect(post(clearancePath(), { approver: 'someone' }).reply.status).toBe(400);
    expect(post(clearancePath(), { tenant: 'a' }).reply.status).toBe(400);
    expect(post(clearancePath(), {}, newFixtureState(), { contentType: 'text/plain' }).reply.status).toBe(415);
    expect(post(clearancePath('not-a-uuid'), {}).reply.status).toBe(400);
    expect(post(clearancePath(ADMIN_PORT, 'Not_Kebab'), {}).reply.status).toBe(400);
  });

  it('answers 404 for a premise with no open reason, and for a premise of another decision', () => {
    expect(post(clearancePath(ADMIN_PORT, 'tls-min-version'), {}).reply.status).toBe(404);
    expect(post(clearancePath(ids.useTls, 'bastion-exists'), {}).reply.status).toBe(404);
    expect(post(clearancePath(ids.useTls, 'unknown-premise'), {}).reply.status).toBe(404);
  });

  it('clears a reason once and takes it out of the list', () => {
    const state = newFixtureState();
    const first = post(clearancePath(), {}, state);
    expect(first.reply).toMatchObject({ status: 201, body: { decision_id: ADMIN_PORT, premise_id: 'bastion-exists' } });
    expect(reasons(state).map((reason) => reason.premise_id)).toEqual(['tls-min-version']);
    expect(post(clearancePath(), {}, state).reply.status).toBe(404);
  });

  it('wants a host and a flag and nothing else', () => {
    expect(post('/v1/premise-hosts', { host: 'a.example.com' }).reply.status).toBe(400);
    expect(post('/v1/premise-hosts', { allowed: true }).reply.status).toBe(400);
    expect(post('/v1/premise-hosts', { host: 'a.example.com', allowed: 'yes' }).reply.status).toBe(400);
    expect(post('/v1/premise-hosts', { host: 'a.example.com', allowed: true, approver: 'x' }).reply.status).toBe(400);
  });

  it('holds a host to a DNS name and never an address', () => {
    for (const host of ['10.0.0.1', '1.2', 'localhost', 'https://a.example.com', 'a.example.com:443', 'a.example.com/x', 'bücher.example', 'a..example.com', '-a.example.com', '']) {
      expect(post('/v1/premise-hosts', { host, allowed: true }).reply.status, host).toBe(400);
    }
    expect(post('/v1/premise-hosts', { host: `${'a'.repeat(64)}.example.com`, allowed: true }).reply.status).toBe(400);
    expect(post('/v1/premise-hosts', { host: 'xn--bcher-kva.example', allowed: true }).reply.status).toBe(201);
  });

  it('lowercases a host, appends a row, and lets the latest row decide', () => {
    const state = newFixtureState();
    const withdrawn = post('/v1/premise-hosts', { host: 'Status.Example.COM', allowed: false }, state);
    expect(withdrawn.reply).toMatchObject({ status: 201, body: { host: 'status.example.com', allowed: false } });
    expect(hosts(state).map(({ host, allowed }) => ({ host, allowed }))).toEqual([
      { host: 'status.example.com', allowed: false },
      { host: 'legacy.example.com', allowed: false },
    ]);
    post('/v1/premise-hosts', { host: 'status.example.com', allowed: true }, state);
    expect(hosts(state)[0]).toMatchObject({ host: 'status.example.com', allowed: true });
    expect(hosts(state)).toHaveLength(2);
  });
});

describe('the export routes of the fixtures server', () => {
  const RECIPIENT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';
  const at = (seconds: number) => new Date(NOW.getTime() + seconds * 1000);
  const get = (path: string, state: ReturnType<typeof newFixtureState>, when = NOW, signedIn = true) =>
    respond({ method: 'GET', url: path, cookie: signedIn ? cookie : '' }, when, state);

  it('needs a session and holds none until one is asked for', () => {
    const state = newFixtureState();
    expect(get('/v1/exports/current', state, NOW, false).status).toBe(401);
    expect(get('/v1/exports/current', state).status).toBe(404);
    expect(get('/v1/exports/0194f2a0-0000-7000-8000-000000000999', state).status).toBe(404);
    expect(get('/v1/exports/current?limit=1', state).status).toBe(400);
  });

  it('refuses a body that is not one public key, and a private key most of all', () => {
    expect(post('/v1/exports', {}).reply.status).toBe(400);
    expect(post('/v1/exports', { recipient: 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQ' }).reply.status).toBe(400);
    expect(post('/v1/exports', { recipient: RECIPIENT, extra: 1 }).reply.status).toBe(400);
    expect(post('/v1/exports', { recipient: `${RECIPIENT}\n${RECIPIENT}` }).reply.status).toBe(400);
  });

  it('makes the export pending, then running, then ready, and sends the archive only then', () => {
    const { reply, state } = post('/v1/exports', { recipient: RECIPIENT });
    expect(reply.status).toBe(202);
    const asked = reply.body as { id: string; state: string; bytes: number | null; sha256: string | null; finished_at: string | null };
    expect(asked).toMatchObject({ state: 'pending', bytes: null, sha256: null, finished_at: null });
    const archive = `/v1/exports/${asked.id}/archive`;
    expect((get('/v1/exports/current', state).body as { state: string }).state).toBe('pending');
    expect((get(`/v1/exports/${asked.id}`, state, at(4)).body as { state: string }).state).toBe('running');
    expect(get(archive, state, at(4)).status).toBe(409);

    const ready = get('/v1/exports/current', state, at(9)).body as { state: string; bytes: number; sha256: string; expires_at: string; finished_at: string };
    expect(ready).toMatchObject({ state: 'ready', bytes: EXPORT_BYTES, sha256: EXPORT_SHA256 });
    expect(Date.parse(ready.expires_at) - Date.parse(ready.finished_at)).toBe(24 * 60 * 60 * 1000);
    const sent = get(archive, state, at(9));
    expect(sent.status).toBe(200);
    expect(sent.headers).toMatchObject({ 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' });
    expect(sent.headers['Content-Disposition']).toBe(`attachment; filename="ipso-export-${asked.id}.age"`);
    expect(new TextEncoder().encode(sent.raw).length).toBe(EXPORT_BYTES);
    expect(createHash('sha256').update(sent.raw ?? '').digest('hex')).toBe(EXPORT_SHA256);
    expect(get('/v1/exports/0194f2a0-0000-7000-8000-000000000999/archive', state, at(9)).status).toBe(404);
  });

  it('refuses a second request while one is under way, and for ten minutes after one finished', () => {
    const { state } = post('/v1/exports', { recipient: RECIPIENT });
    const ask = (when: Date) => respond({ method: 'POST', url: '/v1/exports', cookie, contentType: 'application/json', body: JSON.stringify({ recipient: RECIPIENT }) }, when, state);
    expect(ask(at(4)).status).toBe(409);
    const soon = ask(at(60));
    expect(soon.status).toBe(429);
    expect(Number(soon.headers['Retry-After'])).toBe(10 * 60 - 52);
    const replaced = ask(at(8 + 10 * 60));
    expect(replaced.status).toBe(202);
    expect((replaced.body as { state: string }).state).toBe('pending');
  });

  it('forgets an export 24 hours after it finished', () => {
    const { state } = post('/v1/exports', { recipient: RECIPIENT });
    expect(get('/v1/exports/current', state, at(8 + 24 * 60 * 60 - 1)).status).toBe(200);
    expect(get('/v1/exports/current', state, at(8 + 24 * 60 * 60)).status).toBe(404);
  });
});

describe('the verdict list of the fixtures server', () => {
  const get = (path: string) => respond({ method: 'GET', url: path, cookie }, NOW, newFixtureState());
  const reading = (path: string) => (get(path).body as { known: string; verdicts: { id: string; result: string; baseline: { result: string } | null; waiver: { result: string; expires_at: string | null } | null }[] });

  it('takes the transaction time and answers the time it used, as the registry reads do', () => {
    expect(reading('/v1/verdicts').known).toBe(NOW.toISOString());
    expect(reading('/v1/verdicts?known=2026-11-01T00:00:00Z').known).toBe('2026-11-01T00:00:00Z');
    expect(get('/v1/verdicts?valid=2026-11-01T00:00:00Z').status).toBe(400);
  });

  it('gives each verdict a reading or null, and a reading follows the shape of the document', () => {
    const verdicts = reading('/v1/verdicts').verdicts;
    expect(verdicts.some((verdict) => verdict.baseline === null)).toBe(true);
    expect(verdicts.filter((verdict) => verdict.baseline !== null).map((verdict) => verdict.baseline?.result).sort()).toEqual(['fail', 'waived(baseline)']);
  });

  it('gives a pass no waiver reading and any other verdict one, with the end of the waiver only when it covers', () => {
    const verdicts = reading('/v1/verdicts').verdicts;
    for (const verdict of verdicts) {
      if (verdict.result === 'pass' || verdict.result === 'error') {
        expect(verdict.waiver).toBeNull();
        continue;
      }
      expect(verdict.waiver).not.toBeNull();
      expect(['waived', 'fail']).toContain(verdict.waiver?.result);
      if (verdict.waiver?.result === 'waived') expect(typeof verdict.waiver.expires_at).toBe('string');
      else expect(verdict.waiver?.expires_at).toBeNull();
    }
    expect(verdicts.filter((verdict) => verdict.waiver?.result === 'waived')).toHaveLength(2);
  });
});
