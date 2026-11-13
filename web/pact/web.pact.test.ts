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
import { exportArchivePath, makeCalls } from '../src/api/calls.ts';
import type { Scope } from '../src/api/types.ts';
import { approvalRequest, rejection, type ApprovalForm } from '../src/state/edr.ts';
import {
  checkAnswer,
  grandfatherRequest,
  supersessionRequest,
  waiverRequest,
  type SupersessionForm,
  type WaiverForm,
} from '../src/state/writes.ts';

const { arrayContaining, eachLike, fromProviderState, integer, like, nullValue, regex, uuid } = MatchersV3;

const PACT_DIR = resolve(import.meta.dirname, '../../api/pacts');
const PACT_FILE = resolve(PACT_DIR, 'ipso-web-ipso-server.json');

// The provider states. Every row they describe is synthetic (internal/api/main_integration_test.go).
const REGISTRY = 'tenant A holds decisions, scopes, a waiver, and proposals';
const VERDICTS = 'tenant A holds a stored verdict';
const VIEWER = 'the session belongs to a viewer of tenant A';
// The states of the writes (ADR-0110). A write changes what the provider holds, so each of these states seeds
// its own rows when it is set up and hands their ids back, and the interaction names them with
// fromProviderState. The session is one of a person who may take the action: an approver or a decision owner.
const UNANSWERED = 'tenant A holds drafts that nobody answered, and the session belongs to an approver';
const ANSWERED = 'tenant A holds a draft that was answered, and the session belongs to an approver';
const TO_WAIVE = 'tenant A holds a decision in force and a repository scope, and the session belongs to an approver';
// The states of the answer to a drafted check (ADR-0118). Each seeds a decision and a check drafted for it, and the
// path names both. The session is an approver over the whole tenant, so it covers every scope of the decision.
const CHECK_UNANSWERED = 'tenant A holds a drafted check that nobody answered, and the session belongs to an approver';
const CHECK_ANSWERED = 'tenant A holds a drafted check that was answered, and the session belongs to an approver';
const TO_SUPERSEDE = 'tenant A holds two decisions that nobody superseded, and the session belongs to a decision owner';

// The states of the export (ADR-0115). Each one resets the exports of tenant A and seeds what it names, and the
// session is the admin's: only an admin who is a person takes the export routes (ADR-0108, ADR-0111).
const NO_EXPORT = 'tenant A holds no export, and the session belongs to an admin';
const PENDING_EXPORT = 'tenant A holds a pending export, and the session belongs to an admin';
const READY_EXPORT = 'tenant A holds a ready export, and the session belongs to an admin';
// The age public key of the age documentation. The provider reads it with the same code as ipso-server tenant export.
const AGE_RECIPIENT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';
const EXPORT = '0194f2a0-0000-7000-8000-000000000a01';

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

/** A path is a string, or one the provider state fills in: the id of a row the state seeded. */
type Path = string | ReturnType<typeof fromProviderState<string>>;

interface Interaction {
  description: string;
  state?: string;
  /** GET unless it says otherwise. */
  method?: 'GET' | 'POST';
  path: Path;
  query?: Record<string, string>;
  /** The JSON a write sends. The request then names its content type, as the app's own calls do. */
  requestBody?: unknown;
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
    .withRequest(spec.method ?? 'GET', spec.path, (request) => {
      if (spec.query) request.query(spec.query);
      request.headers({
        Accept: 'application/json',
        ...(spec.requestBody === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(session ? { Cookie: cookie } : {}),
      });
      if (spec.requestBody !== undefined) request.jsonBody(spec.requestBody);
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

  it('is refused by the role policy', async () => {
    await interact(
      {
        description: 'a request for an audit answer from a viewer',
        state: VIEWER,
        path: '/v1/audit/decisions',
        query: { repo: 'acme/api', valid: VALID, known: LATER },
        status: 403,
        body: { error: 'forbidden' },
      },
      async (calls) => {
        await expect(calls.auditDecisions({ repo: 'acme/api', valid: VALID, known: LATER })).rejects.toMatchObject({ status: 403, code: 'forbidden' });
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

// The writes of the web app (IPSO-146, ADR-0110). Each plays the app's own call with the request its own helpers
// build, so the contract holds what a person's click sends and nothing the app would not. The ids a provider
// state seeds are named with fromProviderState, and the values below are only the examples the mock server
// matches. The request never names a tenant, a principal or an approver (ADR-0099).
const SCOPE = '5c9f3b1e-2a7d-4e84-8b6a-1f0d9c2e7a41';
const PROPOSAL = '3d2c6f2e-6b1a-4c6e-9d3b-0a5c1d7e8f90';
const AGENT_PROPOSAL = '9b1d4a7c-0e3f-4a5b-8c2d-6e7f8a9b0c1d';
const DECISION = '7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d';
const FROM = '2b3c4d5e-6f70-4812-93a4-b5c6d7e8f9a0';
const TO = '8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f';
const CHECK_DECISION = '4e5f6a7b-8c9d-4e0f-a1b2-c3d4e5f6a7b8';
const CHECK = '6f7a8b9c-0d1e-4f2a-9b3c-4d5e6f7a8b9c';
const ULID = '01JD8Q3M7K2W9X4Y5Z6A7B8C9D';
const WRITE_FROM = '2026-06-01T00:00:00Z';

const scopeRef = fromProviderState('${scopeId}', SCOPE);
/** The route of the answer to a drafted check, under the decision the check was drafted for. */
const checkPath = fromProviderState('/v1/decisions/${decisionId}/check-proposals/${checkProposalId}/approval', `/v1/decisions/${CHECK_DECISION}/check-proposals/${CHECK}/approval`);
const date = (example: string) => regex('^\\d{4}-\\d{2}-\\d{2}$', example);

const draft: ApprovalForm = {
  title: 'Secrets come from the vault',
  slug: 'secrets-from-the-vault',
  owner: 'team:platform',
  criticality: 'warning',
  validFrom: '2026-11-08',
  reviewBy: '2027-11-08',
  sourceUrl: 'https://github.com/acme/api/pull/8',
  sourceType: 'pr',
};
const scopeTree: Scope[] = [{ id: SCOPE, parent_id: null, kind: 'org', selector: 'acme' }];

/** The decision an approval writes, as the app builds it: all sixteen keys of the EDR (ADR-0110). */
const approved = (source: 'pr' | 'note') => ({
  outcome: 'approved',
  decision: {
    body: {
      edr: 1,
      id: regex('^[0-7][0-9A-HJKMNP-TV-Z]{25}$', ULID),
      slug: like('secrets-from-the-vault'),
      title: like('Secrets come from the vault'),
      status: 'accepted',
      owner: regex('^team:[a-z][a-z0-9]*(-[a-z0-9]+)*$', 'team:platform'),
      scope: [{ org: like('acme') }],
      valid_from: date('2026-11-08'),
      valid_to: nullValue(),
      review_by: date('2027-11-08'),
      supersedes: [],
      criticality: regex('^(blocking|warning|advisory)$', 'warning'),
      checks: [],
      waivers: [],
      sources: [{ type: source, url: regex('^https://\\S+$', 'https://github.com/acme/api/pull/8') }],
      tags: [],
    },
    scope_refs: [scopeRef],
    valid_from: timestamp('2026-11-08T00:00:00Z'),
  },
});

const approval = (outcome: 'approved' | 'rejected') => ({
  id: uuid(),
  proposal_id: uuid(),
  outcome,
  decision_id: outcome === 'approved' ? uuid() : nullValue(),
});

const checkApproval = (outcome: 'approved' | 'rejected') => ({ id: uuid(), proposal_id: uuid(), outcome });

const waiverForm: WaiverForm = {
  decisionId: DECISION,
  scopeId: SCOPE,
  reason: 'The migration is under way',
  ticket: 'SEC-482',
  startsAt: '2026-06-01T00:00',
  endsAt: '2026-07-01T00:00',
};
const supersessionForm: SupersessionForm = { fromId: FROM, toId: TO, effectiveAt: '2026-06-01T00:00', terms: 'baseline', deadline: '' };

describe('the writes of the web app', () => {
  it('approves a proposal from a pull request with the decision the person wrote', async () => {
    await interact(
      {
        description: 'a request to approve a proposal from a pull request',
        state: UNANSWERED,
        method: 'POST',
        path: fromProviderState('/v1/proposals/${proposalId}/approval', `/v1/proposals/${PROPOSAL}/approval`),
        requestBody: approved('pr'),
        status: 201,
        body: approval('approved'),
      },
      async (calls) => {
        const made = await calls.approveProposal(PROPOSAL, approvalRequest(draft, [SCOPE], scopeTree, ULID));
        expect(made.outcome).toBe('approved');
        expect(made.decision_id).not.toBeNull();
      },
    );
  });

  it('approves a proposal from a coding agent through the route of its own queue', async () => {
    await interact(
      {
        description: 'a request to approve a proposal from a coding agent',
        state: UNANSWERED,
        method: 'POST',
        path: fromProviderState('/v1/agent-proposals/${agentProposalId}/approval', `/v1/agent-proposals/${AGENT_PROPOSAL}/approval`),
        requestBody: approved('note'),
        status: 201,
        body: approval('approved'),
      },
      async (calls) => {
        const made = await calls.approveAgentProposal(AGENT_PROPOSAL, approvalRequest({ ...draft, sourceType: 'note' }, [SCOPE], scopeTree, ULID));
        expect(made.outcome).toBe('approved');
      },
    );
  });

  it('rejects a proposal with the outcome and nothing else', async () => {
    await interact(
      {
        description: 'a request to reject a proposal from a pull request',
        state: UNANSWERED,
        method: 'POST',
        path: fromProviderState('/v1/proposals/${proposalId}/approval', `/v1/proposals/${PROPOSAL}/approval`),
        requestBody: { outcome: 'rejected' },
        status: 201,
        body: approval('rejected'),
      },
      async (calls) => {
        expect(await calls.approveProposal(PROPOSAL, rejection)).toMatchObject({ outcome: 'rejected', decision_id: null });
      },
    );
  });

  it('is refused a second answer to a proposal', async () => {
    await interact(
      {
        description: 'a second answer to a proposal',
        state: ANSWERED,
        method: 'POST',
        path: fromProviderState('/v1/proposals/${proposalId}/approval', `/v1/proposals/${PROPOSAL}/approval`),
        requestBody: { outcome: 'rejected' },
        status: 409,
        body: { error: 'conflict' },
      },
      async (calls) => {
        await expect(calls.approveProposal(PROPOSAL, rejection)).rejects.toMatchObject({ status: 409, code: 'conflict' });
      },
    );
  });

  it('approves a drafted check with the outcome and nothing else', async () => {
    await interact(
      {
        description: 'a request to approve a drafted check',
        state: CHECK_UNANSWERED,
        method: 'POST',
        path: checkPath,
        requestBody: { outcome: 'approved' },
        status: 201,
        body: checkApproval('approved'),
      },
      async (calls) => {
        expect(await calls.approveCheckProposal(CHECK_DECISION, CHECK, checkAnswer('approved'))).toMatchObject({ outcome: 'approved' });
      },
    );
  });

  it('rejects a drafted check with the outcome and nothing else', async () => {
    await interact(
      {
        description: 'a request to reject a drafted check',
        state: CHECK_UNANSWERED,
        method: 'POST',
        path: checkPath,
        requestBody: { outcome: 'rejected' },
        status: 201,
        body: checkApproval('rejected'),
      },
      async (calls) => {
        expect(await calls.approveCheckProposal(CHECK_DECISION, CHECK, checkAnswer('rejected'))).toMatchObject({ outcome: 'rejected' });
      },
    );
  });

  it('is refused a second answer to a drafted check', async () => {
    await interact(
      {
        description: 'a second answer to a drafted check',
        state: CHECK_ANSWERED,
        method: 'POST',
        path: checkPath,
        requestBody: { outcome: 'rejected' },
        status: 409,
        body: { error: 'conflict' },
      },
      async (calls) => {
        await expect(calls.approveCheckProposal(CHECK_DECISION, CHECK, checkAnswer('rejected'))).rejects.toMatchObject({ status: 409, code: 'conflict' });
      },
    );
  });

  it('records a waiver with an expiry', async () => {
    await interact(
      {
        description: 'a request to record a waiver',
        state: TO_WAIVE,
        method: 'POST',
        path: '/v1/waivers',
        requestBody: {
          decision_id: fromProviderState('${decisionId}', DECISION),
          scope_id: scopeRef,
          reason: like('The migration is under way'),
          ticket_ref: like('SEC-482'),
          valid_from: timestamp(WRITE_FROM),
          expires_at: timestamp('2026-07-01T00:00:00Z'),
        },
        status: 201,
        body: {
          id: uuid(),
          decision_id: uuid(),
          scope_id: uuid(),
          ticket_ref: like('SEC-482'),
          valid_from: timestamp(WRITE_FROM),
          expires_at: timestamp('2026-07-01T00:00:00Z'),
        },
      },
      async (calls) => {
        expect((await calls.recordWaiver(waiverRequest(waiverForm))).ticket_ref).toBe('SEC-482');
      },
    );
  });

  it('is refused a waiver by the role policy for a viewer', async () => {
    await interact(
      {
        description: 'a request to record a waiver from a viewer',
        state: VIEWER,
        method: 'POST',
        path: '/v1/waivers',
        requestBody: {
          decision_id: DECISION,
          scope_id: SCOPE,
          reason: like('The migration is under way'),
          ticket_ref: like('SEC-482'),
          valid_from: timestamp(WRITE_FROM),
          expires_at: timestamp('2026-07-01T00:00:00Z'),
        },
        status: 403,
        body: { error: 'forbidden' },
      },
      async (calls) => {
        await expect(calls.recordWaiver(waiverRequest(waiverForm))).rejects.toMatchObject({ status: 403, code: 'forbidden' });
      },
    );
  });

  it('records a supersession from a time', async () => {
    await interact(
      {
        description: 'a request to record a supersession',
        state: TO_SUPERSEDE,
        method: 'POST',
        path: '/v1/supersessions',
        requestBody: {
          from_decision: fromProviderState('${fromDecisionId}', FROM),
          to_decision: fromProviderState('${toDecisionId}', TO),
          effective_at: timestamp(WRITE_FROM),
        },
        status: 201,
        body: { id: uuid(), from_decision: uuid(), to_decision: uuid(), effective_at: timestamp(WRITE_FROM) },
      },
      async (calls) => {
        expect((await calls.recordSupersession(supersessionRequest(supersessionForm))).effective_at).toBe(WRITE_FROM);
      },
    );
  });

  it('records the grandfather terms of the new decision', async () => {
    await interact(
      {
        description: 'a request to record the grandfather terms of a decision',
        state: TO_SUPERSEDE,
        method: 'POST',
        path: fromProviderState('/v1/decisions/${toDecisionId}/grandfather-period', `/v1/decisions/${TO}/grandfather-period`),
        requestBody: { valid_from: timestamp(WRITE_FROM) },
        status: 201,
        body: { decision_id: uuid(), valid_from: timestamp(WRITE_FROM), valid_until: nullValue() },
      },
      async (calls) => {
        const request = grandfatherRequest(supersessionForm);
        expect(request).not.toBeNull();
        expect(await calls.recordGrandfatherPeriod(TO, request ?? { valid_from: WRITE_FROM })).toMatchObject({ valid_until: null });
      },
    );
  });
  it('reads the export the tenant holds when it is ready', async () => {
    await interact(
      {
        description: 'a request for the current export when it is ready',
        state: READY_EXPORT,
        path: '/v1/exports/current',
        status: 200,
        body: {
          id: uuid(),
          state: 'ready',
          requested_by: uuid(),
          created_at: timestamp(KNOWN),
          finished_at: timestamp(KNOWN),
          expires_at: timestamp(LATER),
          bytes: integer(1024),
          sha256: sha256('ab'.repeat(32)),
        },
      },
      async (calls) => {
        expect(await calls.currentExport()).toMatchObject({ state: 'ready' });
      },
    );
  });

  it('reads that the tenant holds no export as a 404', async () => {
    await interact(
      {
        description: 'a request for the current export when there is none',
        state: NO_EXPORT,
        path: '/v1/exports/current',
        status: 404,
        body: { error: 'not found' },
      },
      async (calls) => {
        await expect(calls.currentExport()).rejects.toMatchObject({ status: 404, code: 'not found' });
      },
    );
  });

  it('is refused the current export by the role policy for a viewer', async () => {
    await interact(
      {
        description: 'a request for the current export from a viewer',
        state: VIEWER,
        path: '/v1/exports/current',
        status: 403,
        body: { error: 'forbidden' },
      },
      async (calls) => {
        await expect(calls.currentExport()).rejects.toMatchObject({ status: 403, code: 'forbidden' });
      },
    );
  });

  it('asks for an export encrypted to one public key', async () => {
    await interact(
      {
        description: 'a request to start an export',
        state: NO_EXPORT,
        method: 'POST',
        path: '/v1/exports',
        requestBody: { recipient: AGE_RECIPIENT },
        status: 202,
        body: {
          id: uuid(),
          state: 'pending',
          requested_by: uuid(),
          created_at: timestamp(KNOWN),
          finished_at: nullValue(),
          expires_at: timestamp(LATER),
          bytes: nullValue(),
          sha256: nullValue(),
        },
      },
      async (calls) => {
        expect(await calls.startExport({ recipient: AGE_RECIPIENT })).toMatchObject({ state: 'pending', bytes: null });
      },
    );
  });

  it('is refused an export for a key the server cannot read', async () => {
    await interact(
      {
        description: 'a request to start an export for a key the server cannot read',
        state: NO_EXPORT,
        method: 'POST',
        path: '/v1/exports',
        requestBody: { recipient: 'not an age public key' },
        status: 400,
        body: { error: 'invalid query' },
      },
      async (calls) => {
        await expect(calls.startExport({ recipient: 'not an age public key' })).rejects.toMatchObject({ status: 400, code: 'invalid query' });
      },
    );
  });

  it('is refused a second export while one is pending', async () => {
    await interact(
      {
        description: 'a request to start an export while one is pending',
        state: PENDING_EXPORT,
        method: 'POST',
        path: '/v1/exports',
        requestBody: { recipient: AGE_RECIPIENT },
        status: 409,
        body: { error: 'conflict' },
      },
      async (calls) => {
        await expect(calls.startExport({ recipient: AGE_RECIPIENT })).rejects.toMatchObject({ status: 409, code: 'conflict' });
      },
    );
  });

  // The page links to the archive and the browser saves it, so the app makes no call for it. The pact holds the
  // request a click sends and the headers that make it a file. The body is the archive and is not described.
  it('downloads the archive of a ready export as an attachment', async () => {
    await pact
      .addInteraction()
      .given(READY_EXPORT)
      .uponReceiving('a request to download the archive of a ready export')
      .withRequest('GET', fromProviderState('/v1/exports/${exportId}/archive', exportArchivePath(EXPORT)), (request) => {
        request.headers({ Cookie: cookie });
      })
      .willRespondWith(200, (response) => {
        response.headers({
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': regex('^attachment; filename="ipso-export-[0-9a-f-]{36}\\.age"$', `attachment; filename="ipso-export-${EXPORT}.age"`),
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        });
      })
      .executeTest(async (server) => {
        const response = await fetch(`${server.url}${exportArchivePath(EXPORT)}`, {
          headers: { Cookie: COOKIE_EXAMPLE },
          credentials: 'same-origin',
          redirect: 'error',
        });
        expect(response.status).toBe(200);
        expect(response.headers.get('Content-Disposition')).toContain('attachment');
        await response.arrayBuffer();
      });
  });

});
