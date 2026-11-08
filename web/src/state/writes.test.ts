import { describe, expect, it } from 'vitest';

import {
  checkSupersession,
  checkWaiver,
  grandfatherRequest,
  supersessionRequest,
  waiverRequest,
  type SupersessionForm,
  type WaiverForm,
} from './writes';

const A = '0194f2a0-0000-7000-8000-000000000101';
const B = '0194f2a0-0000-7000-8000-000000000102';
const SCOPE = '0194f2a0-0000-7000-8000-000000000005';

const waiver: WaiverForm = {
  decisionId: A,
  scopeId: SCOPE,
  reason: 'The migration is under way',
  ticket: 'SEC-482',
  startsAt: '2026-11-07T12:00',
  endsAt: '2026-12-01T12:00',
};

describe('checkWaiver', () => {
  it('accepts what the server accepts', () => {
    expect(checkWaiver(waiver)).toEqual({});
  });

  it('allows 90 days exactly and refuses a minute more (ADR-0054)', () => {
    expect(checkWaiver({ ...waiver, endsAt: '2027-02-05T12:00' }).endsAt).toBeUndefined();
    expect(checkWaiver({ ...waiver, endsAt: '2027-02-05T12:01' }).endsAt).toMatch(/at most 90 days/);
  });

  it('counts the 90 days as elapsed time, with no regard to the calendar', () => {
    // 2026-03-01 to 2026-05-30 is 90 days of 24 hours.
    expect(checkWaiver({ ...waiver, startsAt: '2026-03-01T00:00', endsAt: '2026-05-30T00:00' }).endsAt).toBeUndefined();
    expect(checkWaiver({ ...waiver, startsAt: '2026-03-01T00:00', endsAt: '2026-05-30T00:01' }).endsAt).toBeDefined();
  });

  it('wants the end after the start', () => {
    expect(checkWaiver({ ...waiver, endsAt: waiver.startsAt }).endsAt).toMatch(/after it starts/);
    expect(checkWaiver({ ...waiver, endsAt: '2026-11-07T11:59' }).endsAt).toMatch(/after it starts/);
  });

  it('wants both times, the decision and the scope', () => {
    const errors = checkWaiver({ ...waiver, decisionId: '', scopeId: 'not-an-id', startsAt: '', endsAt: '' });
    expect(Object.keys(errors).sort()).toEqual(['decisionId', 'endsAt', 'scopeId', 'startsAt']);
  });

  it('holds the reason to 2000 characters and the ticket to 200, counted as characters', () => {
    expect(checkWaiver({ ...waiver, reason: '😀'.repeat(2000) }).reason).toBeUndefined();
    expect(checkWaiver({ ...waiver, reason: '😀'.repeat(2001) }).reason).toBeDefined();
    expect(checkWaiver({ ...waiver, ticket: 'T'.repeat(200) }).ticket).toBeUndefined();
    expect(checkWaiver({ ...waiver, ticket: 'T'.repeat(201) }).ticket).toBeDefined();
    expect(checkWaiver({ ...waiver, reason: '' }).reason).toBeDefined();
  });

  it('refuses a space at either end and a control character, as the server does', () => {
    expect(checkWaiver({ ...waiver, reason: ' padded' }).reason).toBeDefined();
    expect(checkWaiver({ ...waiver, ticket: 'padded ' }).ticket).toBeDefined();
    expect(checkWaiver({ ...waiver, reason: 'two\nlines' }).reason).toMatch(/one line/);
    expect(checkWaiver({ ...waiver, reason: 'tab\there' }).reason).toMatch(/one line/);
  });
});

describe('waiverRequest', () => {
  it('sends the six fields the route lists and the times as UTC', () => {
    expect(waiverRequest(waiver)).toEqual({
      decision_id: A,
      scope_id: SCOPE,
      reason: 'The migration is under way',
      ticket_ref: 'SEC-482',
      valid_from: '2026-11-07T12:00:00Z',
      expires_at: '2026-12-01T12:00:00Z',
    });
  });
});

const supersession: SupersessionForm = { fromId: A, toId: B, effectiveAt: '2026-11-07T12:00', terms: 'none', deadline: '' };

describe('checkSupersession', () => {
  it('accepts two different decisions and a time', () => {
    expect(checkSupersession(supersession)).toEqual({});
  });

  it('refuses a decision that replaces itself', () => {
    expect(checkSupersession({ ...supersession, toId: A }).toId).toMatch(/replace itself/);
  });

  it('wants both decisions and the time', () => {
    expect(Object.keys(checkSupersession({ ...supersession, fromId: '', toId: '', effectiveAt: '' })).sort()).toEqual(['effectiveAt', 'fromId', 'toId']);
  });

  it('wants a deadline only when the terms are a deadline, and after the start', () => {
    expect(checkSupersession({ ...supersession, terms: 'baseline' })).toEqual({});
    expect(checkSupersession({ ...supersession, terms: 'deadline' }).deadline).toBeDefined();
    expect(checkSupersession({ ...supersession, terms: 'deadline', deadline: '2026-11-07T12:00' }).deadline).toMatch(/after the supersession/);
    expect(checkSupersession({ ...supersession, terms: 'deadline', deadline: '2027-01-01T00:00' })).toEqual({});
  });
});

describe('the supersession and its terms', () => {
  it('sends the three fields the route lists', () => {
    expect(supersessionRequest(supersession)).toEqual({ from_decision: A, to_decision: B, effective_at: '2026-11-07T12:00:00Z' });
  });

  it('writes no row for no terms, an open period for a baseline, and a closed one for a deadline (ADR-0052)', () => {
    expect(grandfatherRequest(supersession)).toBeNull();
    expect(grandfatherRequest({ ...supersession, terms: 'baseline', deadline: '2027-01-01T00:00' })).toEqual({ valid_from: '2026-11-07T12:00:00Z' });
    expect(grandfatherRequest({ ...supersession, terms: 'deadline', deadline: '2027-01-01T00:00' })).toEqual({
      valid_from: '2026-11-07T12:00:00Z',
      valid_until: '2027-01-01T00:00:00Z',
    });
  });
});
