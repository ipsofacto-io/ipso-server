// What the server refuses in a waiver and in a supersession, said before the request (ADR-0054, ADR-0052). The
// server stays the authority: a value that passes here can still be refused, and the form shows that answer.
import type { GrandfatherRequest, SupersessionRequest, WaiverRequest } from '../api/types';
import { fieldToTime } from '../lib/format';

export const WAIVER_MAX_DAYS = 90;
export const REASON_MAX = 2000;
export const TICKET_MAX = 200;
const DAY = 24 * 60 * 60 * 1000;
const FIELD_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A datetime-local value, read as UTC, in milliseconds. NaN when it is not a time. */
function fieldMillis(value: string): number {
  return FIELD_TIME.test(value) ? Date.parse(fieldToTime(value)) : Number.NaN;
}

/** The text columns of a waiver: 1 to `max` characters, no space at either end, no control character. */
function textError(value: string, max: number): string | null {
  const length = [...value].length;
  if (length < 1 || length > max || value.trim() !== value) return `Write 1 to ${max} characters with no space at either end.`;
  if (/\p{Cc}/u.test(value)) return 'Use plain text on one line.';
  return null;
}

export interface WaiverForm {
  decisionId: string;
  scopeId: string;
  reason: string;
  ticket: string;
  /** datetime-local values, read as UTC. */
  startsAt: string;
  endsAt: string;
}

export type WaiverErrors = Partial<Record<'decisionId' | 'scopeId' | 'reason' | 'ticket' | 'startsAt' | 'endsAt', string>>;

export function checkWaiver(form: WaiverForm): WaiverErrors {
  const errors: WaiverErrors = {};
  if (!UUID.test(form.decisionId)) errors.decisionId = 'Pick the decision.';
  if (!UUID.test(form.scopeId)) errors.scopeId = 'Pick the scope.';
  const reason = textError(form.reason, REASON_MAX);
  if (reason) errors.reason = reason;
  const ticket = textError(form.ticket, TICKET_MAX);
  if (ticket) errors.ticket = ticket;
  const starts = fieldMillis(form.startsAt);
  const ends = fieldMillis(form.endsAt);
  if (Number.isNaN(starts)) errors.startsAt = 'Pick the time it starts.';
  if (Number.isNaN(ends)) errors.endsAt = 'Pick the time it ends.';
  else if (!Number.isNaN(starts)) {
    // The length is elapsed time, and 90 days exactly is allowed (ADR-0054).
    if (ends <= starts) errors.endsAt = 'It ends after it starts.';
    else if (ends - starts > WAIVER_MAX_DAYS * DAY) errors.endsAt = `A waiver lasts at most ${WAIVER_MAX_DAYS} days.`;
  }
  return errors;
}

export function waiverRequest(form: WaiverForm): WaiverRequest {
  return {
    decision_id: form.decisionId,
    scope_id: form.scopeId,
    reason: form.reason,
    ticket_ref: form.ticket,
    valid_from: fieldToTime(form.startsAt),
    expires_at: fieldToTime(form.endsAt),
  };
}

/** What happens to the code a decision grandfathers (ADR-0052): nothing, a baseline with no end, or a deadline. */
export type Terms = 'none' | 'baseline' | 'deadline';

export interface SupersessionForm {
  fromId: string;
  toId: string;
  effectiveAt: string;
  terms: Terms;
  deadline: string;
}

export type SupersessionErrors = Partial<Record<'fromId' | 'toId' | 'effectiveAt' | 'deadline', string>>;

export function checkSupersession(form: SupersessionForm): SupersessionErrors {
  const errors: SupersessionErrors = {};
  if (!UUID.test(form.fromId)) errors.fromId = 'Pick the decision that ends.';
  if (!UUID.test(form.toId)) errors.toId = 'Pick the decision that replaces it.';
  else if (form.toId === form.fromId) errors.toId = 'A decision cannot replace itself.';
  const effective = fieldMillis(form.effectiveAt);
  if (Number.isNaN(effective)) errors.effectiveAt = 'Pick the time it starts.';
  if (form.terms === 'deadline') {
    const deadline = fieldMillis(form.deadline);
    if (Number.isNaN(deadline)) errors.deadline = 'Pick the deadline.';
    else if (!Number.isNaN(effective) && deadline <= effective) errors.deadline = 'The deadline comes after the supersession starts.';
  }
  return errors;
}

export function supersessionRequest(form: SupersessionForm): SupersessionRequest {
  return { from_decision: form.fromId, to_decision: form.toId, effective_at: fieldToTime(form.effectiveAt) };
}

/** The grandfather terms of the new decision, or null when there are none and no row is written. */
export function grandfatherRequest(form: SupersessionForm): GrandfatherRequest | null {
  if (form.terms === 'none') return null;
  const valid_from = fieldToTime(form.effectiveAt);
  return form.terms === 'baseline' ? { valid_from } : { valid_from, valid_until: fieldToTime(form.deadline) };
}
