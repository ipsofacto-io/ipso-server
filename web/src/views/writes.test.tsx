import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ids } from '../../fixtures/data.ts';
import type { FixtureReply } from '../../fixtures/server.ts';
import { NOW, renderApp, stubFetch } from '../test/render';

const PROPOSAL = '0194f2a0-0000-7000-8000-000000000302';
const AGENT = '0194f2a0-0000-7000-8000-000000000401';
const VAULT = 'Services read secrets from the vault, not from environment files';
const RATE = 'Public endpoints need rate limits';
// A drafted check is answered under the decision it was drafted for (ADR-0116, ADR-0118).
const CHECK = 'the check for decision 0194f2a0, version 2, captured 2026-11-07 11:10 UTC';
const CHECK_ID = '0194f2a0-0000-7000-8000-000000000501';
const CHECK_PATH = `/v1/decisions/${ids.useTls}/check-proposals/${CHECK_ID}/approval`;
const CHECK_QUEUE = 'GET /v1/check-proposals?limit=25';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.title = '';
});

const reply = (status: number, error: string): FixtureReply => ({ status, headers: {}, body: { error } });
const user = () => userEvent.setup({ advanceTimers: () => {} });
const posts = (stub: ReturnType<typeof stubFetch>) => stub.sent.filter((sent) => sent.method === 'POST');
const change = (label: string | RegExp, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });

describe('the inbox actions', () => {
  it('offers approve and reject on a pull request draft, an agent draft and a drafted check', async () => {
    stubFetch();
    renderApp('/inbox');
    await screen.findByText('Check for decision 0194f2a0, version 2');
    expect(screen.getAllByRole('button', { name: /^Approve / })).toHaveLength(4);
    expect(screen.getAllByRole('button', { name: /^Reject / })).toHaveLength(4);
    expect(screen.queryByText(/cannot be approved here yet/)).not.toBeInTheDocument();
    const check = screen.getByText('Check for decision 0194f2a0, version 2').closest('li') as HTMLElement;
    expect(within(check).getByRole('button', { name: `Approve ${CHECK}` })).toBeInTheDocument();
    expect(within(check).getByRole('button', { name: `Reject ${CHECK}` })).toBeInTheDocument();
  });

  it('sends nothing until the person has filled the form in and pressed the button', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${VAULT}` }));
    const form = await screen.findByRole('form', { name: `Approve ${VAULT}` });
    expect(within(form).getByLabelText('Title')).toHaveValue(VAULT);
    expect(within(form).getByLabelText('Slug')).toHaveValue('services-read-secrets-from-the-vault-not-from-environment-files');
    expect(within(form).getByLabelText('Source')).toHaveValue('https://github.com/acme/payments/pull/412');
    expect(within(form).getByLabelText('Starts')).toHaveValue('2026-11-07');
    expect(within(form).getByLabelText('Review by')).toHaveValue('2027-11-07');
    expect(within(form).getByText('Secrets are read from the vault at start.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('says what is missing before it sends, field by field', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${VAULT}` }));
    await screen.findByRole('checkbox', { name: 'repo acme/payments' });
    await u.click(screen.getByRole('button', { name: 'Approve and record the decision' }));
    expect(await screen.findByText(/An owner is a team/)).toBeInTheDocument();
    expect(screen.getByText('Pick at least one scope.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('approves a pull request draft with the decision the person wrote, and the draft leaves the queue', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${VAULT}` }));
    const form = await screen.findByRole('form', { name: `Approve ${VAULT}` });
    change('Owner', 'team:platform');
    await u.click(await within(form).findByRole('checkbox', { name: 'repo acme/payments' }));
    await u.click(within(form).getByRole('checkbox', { name: 'env prod' }));
    await u.click(within(form).getByRole('button', { name: 'Approve and record the decision' }));

    const status = await screen.findByText(`Approved "${VAULT}".`);
    expect(status.closest('[role="status"]')).not.toBeNull();
    const [sent, ...others] = posts(stub);
    expect(others).toHaveLength(0);
    expect(sent).toMatchObject({ method: 'POST', url: `/v1/proposals/${PROPOSAL}/approval`, contentType: 'application/json' });
    const body = JSON.parse(sent?.body ?? '{}');
    expect(Object.keys(body).sort()).toEqual(['decision', 'outcome']);
    expect(body.outcome).toBe('approved');
    expect(body.decision.scope_refs).toEqual([ids.repo, ids.prod]);
    expect(body.decision.valid_from).toBe('2026-11-07T00:00:00Z');
    expect(body.decision.body).toMatchObject({
      edr: 1,
      slug: 'services-read-secrets-from-the-vault-not-from-environment-files',
      title: VAULT,
      status: 'accepted',
      owner: 'team:platform',
      criticality: 'warning',
      valid_from: '2026-11-07',
      valid_to: null,
      review_by: '2027-11-07',
      scope: [
        { org: 'acme', repo: 'acme/payments' },
        { org: 'acme', repo: 'acme/payments', env: ['prod'] },
      ],
      sources: [{ type: 'pr', url: 'https://github.com/acme/payments/pull/412' }],
    });
    expect(body.decision.body.id).toMatch(/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/);
    // The tenant and the approver come from the session and are never in the request.
    expect(sent?.body).not.toMatch(/tenant|principal|approver/i);

    // The queue was read again, and the draft that was answered is not in it.
    await waitFor(() => expect(screen.queryByRole('button', { name: `Approve ${VAULT}` })).not.toBeInTheDocument());
    expect(stub.requests.filter((request) => request === 'GET /v1/proposals?limit=25')).toHaveLength(2);
    expect(within(status.closest('[role="status"]') as HTMLElement).getByRole('link', { name: 'Open the decision' })).toHaveAttribute('href', expect.stringMatching(/^\/decisions\/0194f2a0-/));
  });

  it('approves an agent draft through the route of its own queue, with a source the person gives', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${RATE}` }));
    const form = await screen.findByRole('form', { name: `Approve ${RATE}` });
    expect(within(form).getByLabelText('Criticality')).toHaveValue('warning');
    expect(within(form).getByLabelText('Source')).toHaveValue('');
    change('Owner', 'team:appsec');
    change('Source', 'https://wiki.example.test/rate-limits');
    await u.click(await within(form).findByRole('checkbox', { name: 'org acme' }));
    await u.click(within(form).getByRole('button', { name: 'Approve and record the decision' }));
    await screen.findByText(`Approved "${RATE}".`);
    const [sent] = posts(stub);
    expect(sent?.url).toBe(`/v1/agent-proposals/${AGENT}/approval`);
    expect(JSON.parse(sent?.body ?? '{}').decision.body.sources).toEqual([{ type: 'note', url: 'https://wiki.example.test/rate-limits' }]);
  });

  it('rejects only after a second click, with a body that holds the outcome and nothing else', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${RATE}` }));
    const group = await screen.findByRole('group', { name: `Reject ${RATE}` });
    expect(within(group).getByText(/cannot be reopened/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
    await u.click(within(group).getByRole('button', { name: 'Reject the draft' }));
    await screen.findByText(`Rejected "${RATE}".`);
    const [sent] = posts(stub);
    expect(sent).toMatchObject({ url: `/v1/agent-proposals/${AGENT}/approval`, body: '{"outcome":"rejected"}' });
    await waitFor(() => expect(screen.queryByRole('button', { name: `Reject ${RATE}` })).not.toBeInTheDocument());
  });

  it('closes the confirmation with Cancel and sends nothing', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${RATE}` }));
    await u.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: `Reject ${RATE}` })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: `Reject ${RATE}` })).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('says in words that no role allows it, and keeps the form for the person to read', async () => {
    const stub = stubFetch({ override: ({ method }) => (method === 'POST' ? reply(403, 'forbidden') : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${RATE}` }));
    await u.click(await screen.findByRole('button', { name: 'Reject the draft' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.getByRole('group', { name: `Reject ${RATE}` })).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
  });

  it('reads the queue again when a draft was answered first, and says so above the cards', async () => {
    const stub = stubFetch({ override: ({ method }) => (method === 'POST' ? reply(409, 'conflict') : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${RATE}` }));
    await u.click(await screen.findByRole('button', { name: 'Reject the draft' }));
    expect(await screen.findByText('This draft was already answered.')).toBeInTheDocument();
    await waitFor(() => expect(stub.requests.filter((request) => request === 'GET /v1/agent-proposals?limit=25')).toHaveLength(2));
  });

  it('sends one request for a double click', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${RATE}` }));
    const button = await screen.findByRole('button', { name: 'Reject the draft' });
    await u.dblClick(button);
    await screen.findByText(`Rejected "${RATE}".`);
    expect(posts(stub)).toHaveLength(1);
  });
});

describe('answering a drafted check', () => {
  it('approves only after a confirmation, with a body that holds the outcome and nothing else, and the check leaves the queue', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${CHECK}` }));
    const group = await screen.findByRole('group', { name: `Approve ${CHECK}` });
    expect(within(group).getByText(/writes no decision/)).toBeInTheDocument();
    expect(within(group).getByText(/reaches no repository yet/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
    await u.click(within(group).getByRole('button', { name: 'Approve the check' }));
    expect(await screen.findByText(`Approved ${CHECK}.`)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(posts(stub)[0]).toMatchObject({ url: CHECK_PATH, body: '{"outcome":"approved"}', contentType: 'application/json' });
    await waitFor(() => expect(screen.queryByText('Check for decision 0194f2a0, version 2')).not.toBeInTheDocument());
    expect(screen.getByText('No drafted check waits for review.')).toBeInTheDocument();
    expect(stub.requests.filter((request) => request === CHECK_QUEUE)).toHaveLength(2);
  });

  it('rejects after a confirmation that says the rule is not drafted again', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${CHECK}` }));
    const group = await screen.findByRole('group', { name: `Reject ${CHECK}` });
    expect(within(group).getByText(/not drafted again/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
    await u.click(within(group).getByRole('button', { name: 'Reject the check' }));
    expect(await screen.findByText(`Rejected ${CHECK}.`)).toBeInTheDocument();
    expect(posts(stub)[0]).toMatchObject({ url: CHECK_PATH, body: '{"outcome":"rejected"}' });
    await waitFor(() => expect(screen.queryByText('Check for decision 0194f2a0, version 2')).not.toBeInTheDocument());
  });

  it('closes the confirmation with Cancel and sends nothing', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${CHECK}` }));
    const group = await screen.findByRole('group', { name: `Approve ${CHECK}` });
    await u.click(within(group).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: `Approve ${CHECK}` })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: `Approve ${CHECK}` })).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('moves the focus into the confirmation, and back to the buttons after Cancel', async () => {
    stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${CHECK}` }));
    const group = await screen.findByRole('group', { name: `Reject ${CHECK}` });
    expect(group).toHaveFocus();
    await u.click(within(group).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.getByRole('button', { name: `Approve ${CHECK}` })).toHaveFocus());
  });

  it('answers the check, and not a draft, through the route under its decision', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${CHECK}` }));
    await u.click(await screen.findByRole('button', { name: 'Reject the check' }));
    await screen.findByText(`Rejected ${CHECK}.`);
    expect(posts(stub).map((sent) => sent.url)).toEqual([CHECK_PATH]);
    expect(screen.getByRole('button', { name: `Reject ${RATE}` })).toBeInTheDocument();
  });

  it('says in words that no role allows it, keeps the confirmation, and does not sign the person out', async () => {
    const stub = stubFetch({ override: ({ method }) => (method === 'POST' ? reply(403, 'forbidden') : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${CHECK}` }));
    await u.click(await screen.findByRole('button', { name: 'Approve the check' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.getByRole('group', { name: `Approve ${CHECK}` })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(stub.requests.filter((request) => request === CHECK_QUEUE)).toHaveLength(1);
  });

  it.each([
    [409, 'conflict'],
    [404, 'not found'],
  ])('reads the queue again and says so when the answer is a %i', async (status, code) => {
    const stub = stubFetch({ override: ({ method }) => (method === 'POST' ? reply(status, code) : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${CHECK}` }));
    await u.click(await screen.findByRole('button', { name: 'Reject the check' }));
    expect(await screen.findByText('This draft was already answered.')).toBeInTheDocument();
    await waitFor(() => expect(stub.requests.filter((request) => request === CHECK_QUEUE)).toHaveLength(2));
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });

  it('says to try again for a 429 and does not sign the person out', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? { status: 429, headers: { 'Retry-After': '30' }, body: { error: 'rate limited' } } : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${CHECK}` }));
    await u.click(await screen.findByRole('button', { name: 'Approve the check' }));
    expect(await screen.findByText('Too many requests.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });

  it('sends one request for a double click', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${CHECK}` }));
    await u.dblClick(await screen.findByRole('button', { name: 'Approve the check' }));
    await screen.findByText(`Approved ${CHECK}.`);
    expect(posts(stub)).toHaveLength(1);
  });

  it('is sent to sign in by a 401', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? reply(401, 'unauthorized') : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Approve ${CHECK}` }));
    await u.click(await screen.findByRole('button', { name: 'Approve the check' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
  });
});

describe('recording a waiver', () => {
  async function fill(u: ReturnType<typeof userEvent.setup>, ends: string) {
    await screen.findByRole('heading', { name: 'Record a waiver' });
    await u.selectOptions(await screen.findByLabelText('Decision'), ids.useTls);
    await u.click(await screen.findByRole('radio', { name: 'env prod' }));
    change('Reason', 'The migration is under way');
    change('Ticket', 'SEC-900');
    change('Ends', ends);
  }

  it('records a waiver with an expiry and says when it ends', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/waivers/new');
    await fill(u, '2026-12-01T12:00');
    expect(screen.getByLabelText('Starts')).toHaveValue('2026-11-07T12:00');
    await u.click(screen.getByRole('button', { name: 'Record the waiver' }));
    expect(await screen.findByText('Waiver recorded.')).toBeInTheDocument();
    expect(screen.getByText(/SEC-900 covers env prod until 2026-12-01 12:00 UTC/)).toBeInTheDocument();
    const [sent] = posts(stub);
    expect(sent).toMatchObject({ method: 'POST', url: '/v1/waivers', contentType: 'application/json' });
    expect(JSON.parse(sent?.body ?? '{}')).toEqual({
      decision_id: ids.useTls,
      scope_id: ids.prod,
      reason: 'The migration is under way',
      ticket_ref: 'SEC-900',
      valid_from: '2026-11-07T12:00:00Z',
      expires_at: '2026-12-01T12:00:00Z',
    });
    expect(screen.getByRole('link', { name: 'See the waivers' })).toHaveAttribute('href', '/waivers');
  });

  it('takes the decision from the address, as a link from a decision page does', async () => {
    stubFetch();
    renderApp(`/waivers/new?decision=${ids.useTls}`);
    expect(await screen.findByLabelText('Decision')).toHaveValue(ids.useTls);
  });

  it('refuses 91 days before it sends anything, and allows 90', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/waivers/new');
    await fill(u, '2027-02-06T12:00');
    await u.click(screen.getByRole('button', { name: 'Record the waiver' }));
    expect(await screen.findByText('A waiver lasts at most 90 days.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
    change('Ends', '2027-02-05T12:00');
    await u.click(screen.getByRole('button', { name: 'Record the waiver' }));
    expect(await screen.findByText('Waiver recorded.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
  });

  it('names what each empty field needs', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/waivers/new');
    await u.click(await screen.findByRole('button', { name: 'Record the waiver' }));
    expect(await screen.findByText('Pick the decision.')).toBeInTheDocument();
    expect(screen.getByText('Pick the scope.')).toBeInTheDocument();
    expect(screen.getByText('Pick the time it ends.')).toBeInTheDocument();
    expect(screen.getAllByText(/Write 1 to \d+ characters/)).toHaveLength(2);
    expect(posts(stub)).toHaveLength(0);
  });

  it('says what a 409 means for a waiver, and keeps what was typed', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? reply(409, 'conflict') : undefined) });
    const u = user();
    renderApp('/waivers/new');
    await fill(u, '2026-12-01T12:00');
    await u.click(screen.getByRole('button', { name: 'Record the waiver' }));
    expect(await screen.findByText(/Check the decision, the scope and both times/)).toBeInTheDocument();
    expect(screen.getByLabelText('Ticket')).toHaveValue('SEC-900');
  });

  it('says no role allows it when the policy refuses the person, as it refuses an agent', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? reply(403, 'forbidden') : undefined) });
    const u = user();
    renderApp('/waivers/new');
    await fill(u, '2026-12-01T12:00');
    await u.click(screen.getByRole('button', { name: 'Record the waiver' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
  });

  it('is reached from the waivers page and from a decision', async () => {
    stubFetch();
    renderApp('/waivers');
    expect(await screen.findByRole('link', { name: 'Record a waiver' })).toHaveAttribute('href', '/waivers/new');
  });
});

describe('recording a supersession', () => {
  async function pick(u: ReturnType<typeof userEvent.setup>) {
    await screen.findByRole('heading', { name: 'Record a supersession' });
    await u.selectOptions(await screen.findByLabelText('Decision that ends'), ids.pinImages);
    await u.selectOptions(screen.getByLabelText('Decision that replaces it'), ids.useTls);
  }

  it('records it from a time, with no grandfather terms, in one request', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/supersessions/new');
    await pick(u);
    expect(screen.getByText(/This cannot be undone from the app/)).toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    expect(await screen.findByText('Supersession recorded.')).toBeInTheDocument();
    expect(screen.getByText(/Base images are pinned by digest is superseded by Public ingress terminates TLS 1.2 or later from 2026-11-07 12:00 UTC/)).toBeInTheDocument();
    expect(screen.getByText('No grandfather terms were recorded.')).toBeInTheDocument();
    const sent = posts(stub);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ url: '/v1/supersessions', contentType: 'application/json' });
    expect(JSON.parse(sent[0]?.body ?? '{}')).toEqual({ from_decision: ids.pinImages, to_decision: ids.useTls, effective_at: '2026-11-07T12:00:00Z' });
  });

  it('takes the old decision from the address', async () => {
    stubFetch();
    renderApp(`/supersessions/new?from=${ids.pinImages}`);
    expect(await screen.findByLabelText('Decision that ends')).toHaveValue(ids.pinImages);
  });

  it('records a deadline as the grandfather period of the new decision, after the supersession', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/supersessions/new');
    await pick(u);
    await u.click(screen.getByRole('radio', { name: /A deadline/ }));
    change('Deadline', '2027-01-01T00:00');
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    expect(await screen.findByText('Supersession recorded.')).toBeInTheDocument();
    expect(screen.getByText(/Grandfather terms were recorded until 2027-01-01 00:00 UTC/)).toBeInTheDocument();
    const sent = posts(stub);
    expect(sent.map((s) => s.url)).toEqual(['/v1/supersessions', `/v1/decisions/${ids.useTls}/grandfather-period`]);
    expect(JSON.parse(sent[1]?.body ?? '{}')).toEqual({ valid_from: '2026-11-07T12:00:00Z', valid_until: '2027-01-01T00:00:00Z' });
  });

  it('records a baseline as a period with no end', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/supersessions/new');
    await pick(u);
    await u.click(screen.getByRole('radio', { name: /A baseline with no end/ }));
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    await screen.findByText('Supersession recorded.');
    expect(JSON.parse(posts(stub)[1]?.body ?? '{}')).toEqual({ valid_from: '2026-11-07T12:00:00Z' });
  });

  it('refuses a decision that replaces itself, and a deadline before the start, before it sends', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/supersessions/new');
    await screen.findByRole('heading', { name: 'Record a supersession' });
    await u.selectOptions(await screen.findByLabelText('Decision that ends'), ids.pinImages);
    await u.selectOptions(screen.getByLabelText('Decision that replaces it'), ids.pinImages);
    await u.click(screen.getByRole('radio', { name: /A deadline/ }));
    change('Deadline', '2026-11-01T00:00');
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    expect(await screen.findByText('A decision cannot replace itself.')).toBeInTheDocument();
    expect(screen.getByText(/The deadline comes after the supersession starts/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('says what a 409 means and writes nothing else when the supersession is refused', async () => {
    const stub = stubFetch({ override: ({ method, url }) => (method === 'POST' && url === '/v1/supersessions' ? reply(409, 'conflict') : undefined) });
    const u = user();
    renderApp('/supersessions/new');
    await pick(u);
    await u.click(screen.getByRole('radio', { name: /A baseline with no end/ }));
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    expect(await screen.findByText(/neither may already be superseded/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Record the supersession' })).toBeEnabled();
  });

  it('says the supersession is recorded when the terms are refused, and sends only the terms again', async () => {
    let refuse = true;
    const stub = stubFetch({
      override: ({ method, url }) => (refuse && method === 'POST' && url.endsWith('/grandfather-period') ? reply(409, 'conflict') : undefined),
    });
    const u = user();
    renderApp('/supersessions/new');
    await pick(u);
    await u.click(screen.getByRole('radio', { name: /A baseline with no end/ }));
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    expect(await screen.findByText('The supersession is recorded, but the grandfather terms are not.')).toBeInTheDocument();
    expect(screen.getByText(/already have grandfather terms/)).toBeInTheDocument();
    expect(screen.getByLabelText('Decision that ends')).toBeDisabled();
    expect(screen.getByRole('link', { name: 'Leave without the terms' })).toHaveAttribute('href', `/decisions/${ids.useTls}`);

    refuse = false;
    await u.click(screen.getByRole('button', { name: 'Record the grandfather terms' }));
    expect(await screen.findByText('Supersession recorded.')).toBeInTheDocument();
    expect(posts(stub).map((s) => s.url)).toEqual(['/v1/supersessions', `/v1/decisions/${ids.useTls}/grandfather-period`, `/v1/decisions/${ids.useTls}/grandfather-period`]);
  });

  it('says no role allows it when the policy refuses the person', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? reply(403, 'forbidden') : undefined) });
    const u = user();
    renderApp('/supersessions/new');
    await pick(u);
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
  });

  it('is reached from a decision, with that decision as the one that ends', async () => {
    stubFetch();
    renderApp(`/decisions/${ids.pinImages}`);
    const link = await screen.findByRole('link', { name: 'Supersede this decision' });
    expect(link).toHaveAttribute('href', `/supersessions/new?from=${ids.pinImages}`);
    expect(screen.getByRole('link', { name: 'Record a waiver' })).toHaveAttribute('href', `/waivers/new?decision=${ids.pinImages}`);
  });
});

describe('a signed-out writer', () => {
  it('is sent to sign in by a 401 on a write', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? { status: 401, headers: {}, body: { error: 'unauthorized' } } : undefined) });
    const u = user();
    renderApp('/inbox');
    await u.click(await screen.findByRole('button', { name: `Reject ${RATE}` }));
    await u.click(await screen.findByRole('button', { name: 'Reject the draft' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
  });
});
