// The contract of the web app (consumer ipso-web) with the control plane API (ADR-0091). The app's own calls
// (src/api/calls.ts) play against the Pact mock server, one interaction at a time, and write
// ../api/pacts/ipso-web-ipso-server.json. `ci / pact` fails when the committed file differs from what this
// writes, and internal/api/pact_provider_integration_test.go verifies it against the handler on PostgreSQL.
//
// The app authenticates with the session cookie (ADR-0099), so each request names a cookie of the right form
// and the provider test swaps in the value of a session it opened.
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';

import { MatchersV3, PactV4 } from '@pact-foundation/pact';
import { beforeAll, describe, expect, it } from 'vitest';

import { createApi } from '../src/api/client.ts';
import { makeCalls } from '../src/api/calls.ts';

const { arrayContaining, eachLike, integer, like, nullValue, regex, uuid } = MatchersV3;

const PACT_DIR = resolve(import.meta.dirname, '../../api/pacts');
const PACT_FILE = resolve(PACT_DIR, 'ipso-web-ipso-server.json');

// The provider states. Every row they describe is synthetic (internal/api/main_integration_test.go).
const REGISTRY = 'tenant A holds decisions, scopes, a waiver, and proposals';
const VERDICTS = 'tenant A holds a stored verdict';

const COOKIE_NAME = '__Host-ipso-session';
const COOKIE_EXAMPLE = `${COOKIE_NAME}=${'A'.repeat(43)}`;
const cookie = regex(`^${COOKIE_NAME}=[A-Za-z0-9_-]{43}$`, COOKIE_EXAMPLE);

// Written out, because the Timestamp matcher uses a look-ahead, which the matching engine of the FFI lacks.
const RFC3339 = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$';
const timestamp = (example: string) => regex(RFC3339, example);
const sha256 = (example: string) => regex('^[0-9a-f]{64}$', example);

const VALID = '2026-06-01T00:00:00Z';
const KNOWN = '2026-11-01T00:00:00Z';
// A time after every row the provider seeds, so an audit question reads all of them.
const LATER = '2099-01-01T00:00:00Z';

const decision = {
  id: uuid(),
  version: integer(1),
  body: like({ slug: 'use-tls', title: 'use-tls' }),
};
const decisionPage = {
  valid: timestamp(VALID),
  known: timestamp(KNOWN),
  decisions: eachLike(decision),
};

const pact = new PactV4({ consumer: 'ipso-web', provider: 'ipso-server', dir: PACT_DIR, logLevel: 'warn' });

type Calls = ReturnType<typeof makeCalls>;

interface Interaction {
  description: string;
  state?: string;
  path: string;
  query?: Record<string, string>;
  /** Whether the request carries the session cookie. Only the 401 interaction does not. */
  session?: boolean;
  status: number;
  headers?: Record<string, unknown>;
  body: unknown;
}

/** Plays one interaction: `run` makes the app's own call against the mock server. */
async function interact(spec: Interaction, run: (calls: Calls) => Promise<void>): Promise<void> {
  const session = spec.session ?? true;
  let builder = pact.addInteraction();
  if (spec.state) builder = builder.given(spec.state);
  await builder
    .uponReceiving(spec.description)
    .withRequest('GET', spec.path, (request) => {
      if (spec.query) request.query(spec.query);
      request.headers({ Accept: 'application/json', ...(session ? { Cookie: cookie } : {}) });
    })
    .willRespondWith(spec.status, (response) => {
      response.headers({ 'Content-Type': 'application/json', ...spec.headers });
      response.jsonBody(spec.body);
    })
    .executeTest(async (server) => {
      const api = createApi({ base: server.url, headers: session ? { Cookie: COOKIE_EXAMPLE } : {} });
      await run(makeCalls(api));
    });
}

beforeAll(() => {
  // The file is written from nothing on every run, so a removed interaction leaves no trace.
  rmSync(PACT_FILE, { force: true });
});

describe('the web app and the control plane API', () => {
  it('is refused without a session', async () => {
    await interact(
      {
        description: 'a request without a session',
        path: '/v1/decisions',
        query: { limit: '50' },
        session: false,
        status: 401,
        headers: { 'WWW-Authenticate': regex('^Bearer realm="ipso"$', 'Bearer realm="ipso"') },
        body: { error: 'unauthorized' },
      },
      async (calls) => {
        await expect(calls.listDecisions({ limit: 50 })).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
      },
    );
  });

  it('lists the decisions in force', async () => {
    await interact(
      { description: 'a request for the decisions in force', state: REGISTRY, path: '/v1/decisions', query: { limit: '50' }, status: 200, body: decisionPage },
      async (calls) => {
        const page = await calls.listDecisions({ limit: 50 });
        expect(page.decisions[0]?.body).toMatchObject({ slug: 'use-tls' });
      },
    );
  });

  it('lists the decisions in force at a time', async () => {
    await interact(
      {
        description: 'a request for the decisions in force at a time',
        state: REGISTRY,
        path: '/v1/decisions',
        query: { valid: VALID, known: LATER, limit: '50' },
        status: 200,
        body: decisionPage,
      },
      async (calls) => {
        expect((await calls.listDecisions({ valid: VALID, known: LATER, limit: 50 })).decisions).not.toHaveLength(0);
      },
    );
  });

  it('reads the decisions a registry id names', async () => {
    await interact(
      { description: 'a request for the decision a registry id names', state: REGISTRY, path: '/v1/decisions/00000000-0000-7000-8000-000000000001', status: 200, body: decisionPage },
      async (calls) => {
        expect((await calls.getDecision('00000000-0000-7000-8000-000000000001')).decisions).toHaveLength(1);
      },
    );
  });

  it('reads the decisions a slug names', async () => {
    await interact(
      { description: 'a request for the decisions a slug names', state: REGISTRY, path: '/v1/decisions/use-tls', status: 200, body: decisionPage },
      async (calls) => {
        expect((await calls.getDecision('use-tls')).decisions).not.toHaveLength(0);
      },
    );
  });

  it('lists the scope tree', async () => {
    await interact(
      {
        description: 'a request for the scope tree',
        state: REGISTRY,
        path: '/v1/scopes',
        query: { limit: '100' },
        status: 200,
        body: {
          known: timestamp(KNOWN),
          scopes: arrayContaining(
            { id: uuid(), parent_id: nullValue(), kind: 'org', selector: like('acme') },
            { id: uuid(), parent_id: uuid(), kind: like('repo'), selector: like('acme/api') },
          ),
        },
      },
      async (calls) => {
        expect((await calls.listScopes({ limit: 100 })).scopes.length).toBeGreaterThan(1);
      },
    );
  });

  it('lists the waivers in force', async () => {
    await interact(
      {
        description: 'a request for the waivers in force',
        state: REGISTRY,
        path: '/v1/waivers',
        query: { valid: VALID, limit: '50' },
        status: 200,
        body: {
          valid: timestamp(VALID),
          known: timestamp(KNOWN),
          waivers: eachLike({
            id: uuid(),
            decision_id: uuid(),
            scope_id: uuid(),
            ticket_ref: like('OPS-1'),
            valid_from: timestamp('2026-05-01T00:00:00Z'),
            expires_at: timestamp('2026-06-10T00:00:00Z'),
          }),
        },
      },
      async (calls) => {
        expect((await calls.listWaivers({ valid: VALID, limit: 50 })).waivers[0]?.ticket_ref).toBe('OPS-1');
      },
    );
  });

  it('lists the proposals from pull requests', async () => {
    await interact(
      {
        description: 'a request for the proposals from pull requests',
        state: REGISTRY,
        path: '/v1/proposals',
        query: { limit: '25' },
        status: 200,
        body: {
          proposals: eachLike({
            id: uuid(),
            kind: 'decision',
            origin: 'llm',
            status: 'pending',
            trust_level: 'untrusted',
            payload: like({ title: 'Use Postgres' }),
            confidence: like(0.8),
            model_id: like('m'),
            prompt_version: like('p'),
            repo: like('acme/api'),
            pr_number: integer(8),
            source_url: regex('^https://github\\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+(#[A-Za-z0-9_-]+)?$', 'https://github.com/acme/api/pull/8'),
            captured_at: timestamp(KNOWN),
          }),
        },
      },
      async (calls) => {
        expect((await calls.listProposals({ limit: 25 })).proposals).toHaveLength(1);
      },
    );
  });

  it('lists the proposals from coding agents', async () => {
    await interact(
      {
        description: 'a request for the proposals from coding agents',
        state: REGISTRY,
        path: '/v1/agent-proposals',
        query: { limit: '25' },
        status: 200,
        body: {
          agent_proposals: eachLike({
            id: uuid(),
            principal_id: uuid(),
            status: 'pending',
            payload: like({ title: 'Pin API versions' }),
            captured_at: timestamp(KNOWN),
          }),
        },
      },
      async (calls) => {
        expect((await calls.listAgentProposals({ limit: 25 })).agent_proposals).toHaveLength(1);
      },
    );
  });

  it('lists the drafted checks', async () => {
    await interact(
      {
        description: 'a request for the drafted checks',
        state: REGISTRY,
        path: '/v1/check-proposals',
        query: { limit: '25' },
        status: 200,
        body: {
          check_proposals: eachLike({
            id: uuid(),
            status: 'pending',
            decision_id: uuid(),
            decision_version: integer(1),
            engine: 'opa',
            target: 'agent-edit',
            spec: like({}),
            rego: like('package p'),
            fixtures: eachLike({}),
            repaired: like(false),
            model_id: like('m'),
            prompt_version: like('p'),
            captured_at: timestamp(KNOWN),
          }),
        },
      },
      async (calls) => {
        expect((await calls.listCheckProposals({ limit: 25 })).check_proposals).toHaveLength(1);
      },
    );
  });

  it('lists the stored verdicts of a decision', async () => {
    await interact(
      {
        description: 'a request for the stored verdicts of a decision',
        state: VERDICTS,
        path: '/v1/verdicts',
        query: { decision: '01M5QJ0V9EVXKR4C89XNBNT5GG', limit: '20' },
        status: 200,
        body: {
          verdicts: eachLike({
            id: uuid(),
            upload_id: uuid(),
            decision_id: like('01M5QJ0V9EVXKR4C89XNBNT5GG'),
            slug: like('use-tls'),
            check_index: integer(0),
            mode: like('block'),
            result: like('fail'),
            violations: integer(2),
            repo: like('acme/api'),
            sha: like('abababababababababababababababababababab'),
            ref: like('refs/heads/main'),
            event: like('push'),
            workflow_ref: like('acme/api/.github/workflows/ci.yml@refs/heads/main'),
            run_id: integer(1001),
            run_attempt: integer(1),
            run_url: like('https://github.com/acme/api/actions/runs/1001'),
            check: like('plan'),
            env: like('prod'),
            ipso_version: like('0.5.0'),
            evaluated_at: timestamp(VALID),
            recorded_at: timestamp(KNOWN),
            build_sha256: sha256('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
            sarif_sha256: sha256('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'),
            evidence: like({ plan_sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }),
          }),
        },
      },
      async (calls) => {
        expect((await calls.listVerdicts({ decision: '01M5QJ0V9EVXKR4C89XNBNT5GG', limit: 20 })).verdicts[0]?.result).toBe('fail');
      },
    );
  });

  it('answers Q1, what applied', async () => {
    await interact(
      {
        description: 'a request for the decisions that applied to a subject',
        state: REGISTRY,
        path: '/v1/audit/decisions',
        query: { repo: 'acme/api', valid: VALID, known: LATER },
        status: 200,
        body: { decisions: eachLike(decision) },
      },
      async (calls) => {
        expect((await calls.auditDecisions({ repo: 'acme/api', valid: VALID, known: LATER })).decisions).not.toHaveLength(0);
      },
    );
  });

  it('answers Q2, what changed', async () => {
    await interact(
      {
        description: 'a request for how the beliefs about a subject changed',
        state: REGISTRY,
        path: '/v1/audit/beliefs',
        query: { repo: 'acme/api', valid: VALID, then: '2000-01-01T00:00:00Z', now: LATER },
        status: 200,
        body: { added: eachLike(decision), removed: [], changed: [] },
      },
      async (calls) => {
        const answer = await calls.auditBeliefs({ repo: 'acme/api', valid: VALID, then: '2000-01-01T00:00:00Z', now: LATER });
        expect(answer.added).not.toHaveLength(0);
        expect(answer.changed).toEqual([]);
      },
    );
  });

  it('answers Q3, at a merge', async () => {
    await interact(
      {
        description: 'a request for the decisions that applied at a merge',
        state: REGISTRY,
        path: '/v1/audit/merges',
        query: { repo: 'acme/api', at: VALID, known: LATER },
        status: 200,
        body: { decisions: eachLike(decision) },
      },
      async (calls) => {
        expect((await calls.auditMerges({ repo: 'acme/api', at: VALID, known: LATER })).decisions).not.toHaveLength(0);
      },
    );
  });

  it('answers Q4, the supersession chain', async () => {
    await interact(
      {
        description: 'a request for the supersession chain of a decision',
        state: REGISTRY,
        path: '/v1/audit/supersessions/00000000-0000-7000-8000-000000000003',
        query: { known: LATER },
        status: 200,
        body: {
          links: eachLike({ id: uuid(), from: uuid(), to: uuid(), effective_at: timestamp('2026-03-01T00:00:00Z') }),
          versions: arrayContaining(
            { decision_id: uuid(), version: integer(1), valid_from: timestamp('2025-01-01T00:00:00Z'), valid_to: timestamp('2026-03-01T00:00:00Z') },
            { decision_id: uuid(), version: integer(1), valid_from: timestamp('2026-01-01T00:00:00Z'), valid_to: nullValue() },
          ),
        },
      },
      async (calls) => {
        const chain = await calls.auditSupersessions('00000000-0000-7000-8000-000000000003', { known: LATER });
        expect(chain.links).toHaveLength(1);
        expect(chain.versions.map((version) => version.valid_to === null)).toContain(true);
      },
    );
  });

  it('answers Q5, the waivers that end soon', async () => {
    await interact(
      {
        description: 'a request for the waivers that end within 14 days',
        state: REGISTRY,
        path: '/v1/audit/waivers',
        query: { known: LATER, now: VALID },
        status: 200,
        body: {
          waivers: eachLike({
            id: uuid(),
            decision_id: uuid(),
            scope_id: uuid(),
            ticket_ref: like('OPS-1'),
            expires_at: timestamp('2026-06-10T00:00:00Z'),
          }),
        },
      },
      async (calls) => {
        expect((await calls.auditWaivers({ known: LATER, now: VALID })).waivers[0]?.ticket_ref).toBe('OPS-1');
      },
    );
  });
});
