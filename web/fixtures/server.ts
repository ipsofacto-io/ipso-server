// A stand-in for the control plane, as far as the web app uses it. It keeps the rules of the real one that a
// client can break: no session is a 401, a query key the route does not list is a 400, a list pages by id from
// the highest, a write needs a JSON body with no key the route does not list, and a draft is answered once.
// `respond` takes the state of its writes as an argument, so a test starts from nothing and `npm run fixtures`
// keeps one state for as long as it runs. The role policy is not played here: every person may write.
import type { Decision, Waiver } from '../src/api/types.ts';
import { agentProposals, checkProposals, decisions, ids, proposals, scopes, verdicts, waivers } from './data.ts';

export interface FixtureRequest {
  method: string;
  /** The path and the query, as the server received them. */
  url: string;
  cookie: string;
  /** The Content-Type of a write, and the body as text. */
  contentType?: string;
  body?: string;
}

/** What the writes of one run changed. */
export interface FixtureState {
  /** The ids of the drafts a person answered. An answered draft leaves its queue. */
  answered: Set<string>;
  decisions: Decision[];
  waivers: Waiver[];
  /** The decisions that have a successor: a decision is superseded once. */
  superseded: Set<string>;
  /** The decisions that have grandfather terms: a decision has one set. */
  terms: Set<string>;
  sequence: number;
}

export function newFixtureState(): FixtureState {
  return { answered: new Set(), decisions: [], waivers: [], superseded: new Set([ids.legacyFtp]), terms: new Set(), sequence: 1000 };
}

export interface FixtureReply {
  status: number;
  headers: Record<string, string>;
  body?: unknown;
}

export const SESSION_COOKIE = 'fixtures-session';

const json = (status: number, body: unknown, headers: Record<string, string> = {}): FixtureReply => ({ status, headers, body });
const error = (status: number, code: string, headers: Record<string, string> = {}): FixtureReply => json(status, { error: code }, headers);

const PAGED = ['limit', 'before'];
const TIMES = ['valid', 'known'];
const SUBJECT = ['repo', 'path', 'env'];

function page<T extends { id: string }>(items: T[], query: URLSearchParams): T[] {
  const limit = Math.min(Math.max(Number(query.get('limit') ?? 50) || 50, 1), 100);
  const before = query.get('before');
  return [...items]
    .sort((a, b) => (a.id < b.id ? 1 : -1))
    .filter((item) => before === null || item.id < before)
    .slice(0, limit);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const MAX_BODY = 1 << 20;
const WAIVER_MAX = 90 * 24 * 60 * 60 * 1000;

type Fields = Record<string, unknown>;
type Parsed = { ok: true; fields: Fields } | { ok: false; reply: FixtureReply };

const isTime = (value: unknown): value is string => typeof value === 'string' && TIME.test(value) && !Number.isNaN(Date.parse(value));
const isUuid = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);
const isRecord = (value: unknown): value is Fields => typeof value === 'object' && value !== null && !Array.isArray(value);

/** One text column of a waiver: 1 to `max` characters, no space at either end, no control character. */
function isText(value: unknown, max: number): value is string {
  if (typeof value !== 'string') return false;
  const length = [...value].length;
  return length >= 1 && length <= max && value.trim() === value && !/\p{Cc}/u.test(value);
}

/** The body of a write: JSON, an object, and no key the route does not list. */
function parse(request: FixtureRequest, allowed: string[]): Parsed {
  if (!/^application\/json\s*(;|$)/i.test(request.contentType ?? '')) return { ok: false, reply: error(415, 'unsupported media type') };
  const text = request.body ?? '';
  if (text.length > MAX_BODY) return { ok: false, reply: error(413, 'too large') };
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reply: error(400, 'invalid query') };
  }
  if (!isRecord(value) || Object.keys(value).some((key) => !allowed.includes(key))) return { ok: false, reply: error(400, 'invalid query') };
  return { ok: true, fields: value };
}

const fresh = (state: FixtureState): string => `0194f2a0-0000-7000-8000-${String(++state.sequence).padStart(12, '0')}`;

function write(request: FixtureRequest, path: string, now: Date, state: FixtureState): FixtureReply {
  const known = (id: string) => [...decisions, ...state.decisions].some((decision) => decision.id === id);
  const bad = error(400, 'invalid query');

  const approval = /^\/v1\/(proposals|agent-proposals)\/([^/]+)\/approval$/.exec(path);
  if (approval) {
    const id = decodeURIComponent(approval[2] ?? '');
    const parsed = parse(request, ['outcome', 'decision']);
    if (!parsed.ok) return parsed.reply;
    const { outcome, decision } = parsed.fields;
    if (outcome !== 'approved' && outcome !== 'rejected') return bad;
    if ((outcome === 'approved') !== (decision !== undefined)) return bad;
    let draft: Fields | null = null;
    if (outcome === 'approved') {
      if (!isRecord(decision) || Object.keys(decision).some((key) => !['body', 'scope_refs', 'valid_from'].includes(key))) return bad;
      const { body, scope_refs: refs, valid_from: from } = decision;
      if (!isRecord(body) || typeof body.slug !== 'string' || !SLUG.test(body.slug) || body.slug.length > 128) return bad;
      if (typeof body.title !== 'string' || [...body.title].length < 1 || [...body.title].length > 300 || body.title.trim() !== body.title) return bad;
      if (!Array.isArray(refs) || refs.length < 1 || refs.length > 100 || !refs.every((ref) => scopes.some((scope) => scope.id === ref))) return bad;
      if (!isTime(from)) return bad;
      draft = body;
    }
    const queue = approval[1] === 'proposals' ? proposals(now) : agentProposals(now);
    if (!queue.some((item) => item.id === id)) return error(404, 'not found');
    if (state.answered.has(id)) return error(409, 'conflict');
    state.answered.add(id);
    let decisionId: string | null = null;
    if (draft) {
      decisionId = fresh(state);
      state.decisions.push({ id: decisionId, version: 1, body: draft });
    }
    return json(201, { id: fresh(state), proposal_id: id, outcome, decision_id: decisionId });
  }

  if (path === '/v1/waivers') {
    const parsed = parse(request, ['decision_id', 'scope_id', 'reason', 'ticket_ref', 'valid_from', 'expires_at']);
    if (!parsed.ok) return parsed.reply;
    const { decision_id: decision, scope_id: scope, reason, ticket_ref: ticket, valid_from: from, expires_at: until } = parsed.fields;
    if (!isUuid(decision) || !isUuid(scope) || !isText(reason, 2000) || !isText(ticket, 200) || !isTime(from) || !isTime(until)) return bad;
    const length = Date.parse(until) - Date.parse(from);
    if (length <= 0 || length > WAIVER_MAX) return bad;
    if (!known(decision) || !scopes.some((candidate) => candidate.id === scope)) return error(404, 'not found');
    const waiver: Waiver = { id: fresh(state), decision_id: decision, scope_id: scope, ticket_ref: ticket, valid_from: from, expires_at: until };
    state.waivers.push(waiver);
    return json(201, waiver);
  }

  if (path === '/v1/supersessions') {
    const parsed = parse(request, ['from_decision', 'to_decision', 'effective_at']);
    if (!parsed.ok) return parsed.reply;
    const { from_decision: from, to_decision: to, effective_at: at } = parsed.fields;
    if (!isUuid(from) || !isUuid(to) || !isTime(at) || from === to) return bad;
    if (!known(from) || !known(to)) return error(404, 'not found');
    if (state.superseded.has(from) || state.superseded.has(to)) return error(409, 'conflict');
    state.superseded.add(from);
    return json(201, { id: fresh(state), from_decision: from, to_decision: to, effective_at: at });
  }

  const period = /^\/v1\/decisions\/([^/]+)\/grandfather-period$/.exec(path);
  if (period) {
    const id = decodeURIComponent(period[1] ?? '');
    const parsed = parse(request, ['valid_from', 'valid_until']);
    if (!parsed.ok) return parsed.reply;
    const { valid_from: from, valid_until: until = null } = parsed.fields;
    if (!isTime(from) || (until !== null && (!isTime(until) || Date.parse(until) <= Date.parse(from)))) return bad;
    if (!known(id)) return error(404, 'not found');
    if (state.terms.has(id)) return error(409, 'conflict');
    state.terms.add(id);
    return json(201, { decision_id: id, valid_from: from, valid_until: until });
  }
  return error(404, 'not found');
}

export function respond(request: FixtureRequest, now: Date = new Date(), state: FixtureState = newFixtureState()): FixtureReply {
  const url = new URL(request.url, 'http://fixtures.invalid');
  const path = url.pathname;
  const query = url.searchParams;
  const signedIn = request.cookie.split(';').some((part) => part.trim() === `${SESSION_COOKIE}=1`);

  if (path === '/auth/providers' && request.method === 'GET') {
    return json(200, { providers: [{ id: 'dex', kind: 'oidc' }, { id: 'github', kind: 'github' }] });
  }
  if (path.startsWith('/auth/login/') && request.method === 'GET') {
    return { status: 303, headers: { Location: '/', 'Set-Cookie': `${SESSION_COOKIE}=1; Path=/; SameSite=Strict` } };
  }
  if (path === '/auth/logout' && request.method === 'POST') {
    return { status: 204, headers: { 'Set-Cookie': `${SESSION_COOKIE}=; Path=/; Max-Age=0` } };
  }
  if (!path.startsWith('/v1/')) return error(404, 'not found');
  if (!signedIn) return error(401, 'unauthorized', { 'WWW-Authenticate': 'Bearer realm="ipso"' });
  if (request.method === 'POST') return write(request, path, now, state);
  if (request.method !== 'GET') return error(404, 'not found');
  const everyDecision = [...decisions, ...state.decisions];

  const allow = (...keys: string[]): FixtureReply | null => {
    const seen = new Set<string>();
    for (const key of query.keys()) {
      if (!keys.includes(key) || seen.has(key)) return error(400, 'invalid query');
      seen.add(key);
    }
    return null;
  };
  const need = (...keys: string[]): FixtureReply | null => (keys.every((key) => query.get(key)) ? null : error(400, 'invalid query'));
  const echo = { valid: query.get('valid') ?? now.toISOString(), known: query.get('known') ?? now.toISOString() };

  if (path === '/v1/decisions') {
    return allow(...TIMES, ...PAGED) ?? json(200, { ...echo, decisions: page(everyDecision, query) });
  }
  if (path.startsWith('/v1/decisions/')) {
    const ref = decodeURIComponent(path.slice('/v1/decisions/'.length));
    return allow(...TIMES) ?? json(200, { ...echo, decisions: everyDecision.filter((d) => d.id === ref || d.body.slug === ref) });
  }
  if (path === '/v1/scopes') return allow('known', ...PAGED) ?? json(200, { known: echo.known, scopes: page(scopes, query) });
  if (path === '/v1/waivers') return allow(...TIMES, ...PAGED) ?? json(200, { ...echo, waivers: page([...waivers(now), ...state.waivers], query) });
  if (path === '/v1/proposals') return allow(...PAGED) ?? json(200, { proposals: page(proposals(now).filter((p) => !state.answered.has(p.id)), query) });
  if (path === '/v1/agent-proposals') return allow(...PAGED) ?? json(200, { agent_proposals: page(agentProposals(now).filter((p) => !state.answered.has(p.id)), query) });
  if (path === '/v1/check-proposals') return allow(...PAGED) ?? json(200, { check_proposals: page(checkProposals(now), query) });
  if (path === '/v1/verdicts') {
    const refused = allow('repo', 'decision', ...PAGED);
    if (refused) return refused;
    const decision = query.get('decision');
    const repo = query.get('repo');
    const rows = verdicts(now).filter((v) => (decision === null || v.decision_id === decision || v.slug === decision) && (repo === null || v.repo === repo.toLowerCase()));
    return json(200, { verdicts: page(rows, query) });
  }

  if (path === '/v1/audit/decisions') {
    return allow(...SUBJECT, 'valid', 'known') ?? need('repo', 'valid', 'known') ?? json(200, { decisions: decisions.slice(-3) });
  }
  if (path === '/v1/audit/merges') {
    return allow(...SUBJECT, 'at', 'known') ?? need('repo', 'at') ?? json(200, { decisions: decisions.slice(-2) });
  }
  if (path === '/v1/audit/beliefs') {
    const refused = allow(...SUBJECT, 'valid', 'then', 'now') ?? need('repo', 'valid', 'then', 'now');
    if (refused) return refused;
    const now = decisions.find((d) => d.id === ids.useTls)!;
    const then = { ...now, version: 1, body: { ...now.body, status: 'accepted' } };
    return json(200, { added: [decisions.find((d) => d.id === ids.noEval)], removed: [decisions.find((d) => d.id === ids.postgresOnly)], changed: [{ id: ids.useTls, then, now }] });
  }
  if (path.startsWith('/v1/audit/supersessions/')) {
    const id = decodeURIComponent(path.slice('/v1/audit/supersessions/'.length));
    const refused = allow('known') ?? need('known');
    if (refused) return refused;
    if (id !== ids.legacyFtp && id !== ids.sftpOnly) return json(200, { links: [], versions: [] });
    return json(200, {
      links: [{ id: '0194f2a0-0000-7000-8000-000000000801', from: ids.legacyFtp, to: ids.sftpOnly, effective_at: '2026-06-01T00:00:00Z' }],
      versions: [
        { decision_id: ids.legacyFtp, version: 3, valid_from: '2025-01-01T00:00:00Z', valid_to: '2026-06-01T00:00:00Z' },
        { decision_id: ids.sftpOnly, version: 1, valid_from: '2026-06-01T00:00:00Z', valid_to: null },
      ],
    });
  }
  if (path === '/v1/audit/waivers') {
    const refused = allow('known', 'now') ?? need('known', 'now');
    if (refused) return refused;
    return json(200, { waivers: waivers(now).slice(0, 2).map(({ valid_from: _from, ...rest }) => rest) });
  }
  return error(404, 'not found');
}
