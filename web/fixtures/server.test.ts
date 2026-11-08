import { describe, expect, it } from 'vitest';

import { ids, scopes } from './data.ts';
import { newFixtureState, respond, SESSION_COOKIE, type FixtureRequest } from './server.ts';

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
