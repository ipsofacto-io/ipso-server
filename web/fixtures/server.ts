// A stand-in for the control plane, as far as the web app uses it. It keeps the rules of the real one that a
// client can break: no session is a 401, a query key the route does not list is a 400, and a list pages by id
// from the highest. `respond` is pure, so the tests and the Vite plugin share it.
import { agentProposals, checkProposals, decisions, ids, proposals, scopes, verdicts, waivers } from './data.ts';

export interface FixtureRequest {
  method: string;
  /** The path and the query, as the server received them. */
  url: string;
  cookie: string;
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

export function respond(request: FixtureRequest, now: Date = new Date()): FixtureReply {
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
  if (request.method !== 'GET') return error(404, 'not found');

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
    return allow(...TIMES, ...PAGED) ?? json(200, { ...echo, decisions: page(decisions, query) });
  }
  if (path.startsWith('/v1/decisions/')) {
    const ref = decodeURIComponent(path.slice('/v1/decisions/'.length));
    return allow(...TIMES) ?? json(200, { ...echo, decisions: decisions.filter((d) => d.id === ref || d.body.slug === ref) });
  }
  if (path === '/v1/scopes') return allow('known', ...PAGED) ?? json(200, { known: echo.known, scopes: page(scopes, query) });
  if (path === '/v1/waivers') return allow(...TIMES, ...PAGED) ?? json(200, { ...echo, waivers: page(waivers(now), query) });
  if (path === '/v1/proposals') return allow(...PAGED) ?? json(200, { proposals: page(proposals(now), query) });
  if (path === '/v1/agent-proposals') return allow(...PAGED) ?? json(200, { agent_proposals: page(agentProposals(now), query) });
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
