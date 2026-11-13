import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ids } from '../../fixtures/data.ts';
import type { FixtureReply } from '../../fixtures/server.ts';
import { NOW, renderApp, stubFetch } from '../test/render';

// The reasons the fixtures server holds, as the page names them: the premise and the full id of its decision.
const TLS = `the review reason of premise tls-min-version of decision ${ids.useTls}`;
const BASTION = `the review reason of premise bastion-exists of decision ${ids.adminPort}`;
const TLS_PATH = `/v1/decisions/${ids.useTls}/premises/tls-min-version/clearance`;
const BASTION_PATH = `/v1/decisions/${ids.adminPort}/premises/bastion-exists/clearance`;
const REASONS = 'GET /v1/premise-reasons?limit=25';
const HOSTS = 'GET /v1/premise-hosts?limit=25';
const MARKUP = '<img src=x onerror="alert(1)">';

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
const reasons = () => within(screen.getByRole('region', { name: 'Open review reasons' }));
const allowlist = () => within(screen.getByRole('region', { name: 'Allowlist' }));
const onWrite = (answer: FixtureReply) => ({ override: ({ method }: { method: string }) => (method === 'POST' ? answer : undefined) });

describe('the open review reasons', () => {
  it('lists each reason with the fail that opened it, newest first', async () => {
    stubFetch();
    renderApp('/premises');
    expect(await screen.findByRole('heading', { name: 'Premises', level: 1 })).toBeInTheDocument();
    const cards = await reasons().findAllByRole('listitem');
    expect(cards.map((card) => within(card).getByRole('heading').textContent)).toEqual(['Premise tls-min-version', 'Premise bastion-exists']);
    const bastion = within(cards[1] as HTMLElement);
    expect(bastion.getByRole('link', { name: '0194f2a0' })).toHaveAttribute('href', `/decisions/${ids.adminPort}`);
    expect(bastion.getByText('2026-11-06 06:00 UTC')).toBeInTheDocument();
    expect(bastion.getByText('/reachable')).toBeInTheDocument();
    expect(bastion.getByText('true')).toBeInTheDocument();
    expect(bastion.getByText('false')).toBeInTheDocument();
    expect(bastion.getByText(/read from a public URL/)).toBeInTheDocument();
  });

  it('links an https URL and shows any other as text', async () => {
    stubFetch();
    renderApp('/premises');
    const link = await reasons().findByRole('link', { name: 'https://status.example.com/bastion.json' });
    expect(link).toHaveAttribute('href', 'https://status.example.com/bastion.json');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(reasons().getByText('http://status.example.com/tls.json')).toBeInTheDocument();
    expect(reasons().queryByRole('link', { name: 'http://status.example.com/tls.json' })).not.toBeInTheDocument();
  });

  it('shows an observed value that is markup as text, and makes no element of it', async () => {
    stubFetch();
    renderApp('/premises');
    expect(await reasons().findByText(JSON.stringify(MARKUP))).toBeInTheDocument();
    expect(document.querySelector('main img')).toBeNull();
    expect(document.querySelector('[onerror]')).toBeNull();
  });

  it('shows a stored string in quotes, because the stored value is JSON', async () => {
    stubFetch();
    renderApp('/premises');
    const tls = within((await reasons().findAllByRole('listitem'))[0] as HTMLElement);
    expect(tls.getByText('"1.2"')).toBeInTheDocument();
  });

  it('says that no reason is open when the list is empty', async () => {
    stubFetch({ override: ({ url }) => (url.startsWith('/v1/premise-reasons') ? { status: 200, headers: {}, body: { premise_reasons: [] } } : undefined) });
    renderApp('/premises');
    expect(await screen.findByText('No review reason is open.')).toBeInTheDocument();
  });

  it('clears only after a confirmation, with an empty body, and the reason leaves the list', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${BASTION}` }));
    const group = await screen.findByRole('group', { name: `Clear ${BASTION}` });
    expect(within(group).getByText(/does not change the decision/)).toBeInTheDocument();
    expect(within(group).getByText(/every scope of the decision/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
    await u.click(within(group).getByRole('button', { name: 'Clear the reason' }));
    expect(await screen.findByText(`Cleared ${BASTION}.`)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(posts(stub)[0]).toMatchObject({ url: BASTION_PATH, body: '{}', contentType: 'application/json' });
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Premise bastion-exists' })).not.toBeInTheDocument());
    expect(reasons().getByRole('heading', { name: 'Premise tls-min-version' })).toBeInTheDocument();
    expect(stub.requests.filter((request) => request === REASONS)).toHaveLength(2);
  });

  it('names the premise and the decision in the path, and sends nothing else', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    await u.click(await screen.findByRole('button', { name: 'Clear the reason' }));
    await screen.findByText(`Cleared ${TLS}.`);
    expect(posts(stub).map((sent) => [sent.url, sent.body])).toEqual([[TLS_PATH, '{}']]);
  });

  it('closes the confirmation with Cancel and sends nothing', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    const group = await screen.findByRole('group', { name: `Clear ${TLS}` });
    await u.click(within(group).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: `Clear ${TLS}` })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: `Clear ${TLS}` })).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('moves the focus into the confirmation, and back to the button after Cancel', async () => {
    stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    const group = await screen.findByRole('group', { name: `Clear ${TLS}` });
    expect(group).toHaveFocus();
    await u.click(within(group).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.getByRole('button', { name: `Clear ${TLS}` })).toHaveFocus());
  });

  it('moves the focus to the notice after a clearance, because the button is gone', async () => {
    stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${BASTION}` }));
    await u.click(await screen.findByRole('button', { name: 'Clear the reason' }));
    const notice = (await screen.findByText(`Cleared ${BASTION}.`)).closest('.queue-notice');
    await waitFor(() => expect(notice).toHaveFocus());
  });

  it('says in words that no role allows it, keeps the confirmation, and does not sign the person out', async () => {
    const stub = stubFetch(onWrite(reply(403, 'forbidden')));
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    await u.click(await screen.findByRole('button', { name: 'Clear the reason' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.getByRole('group', { name: `Clear ${TLS}` })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    expect(stub.requests.filter((request) => request === REASONS)).toHaveLength(1);
  });

  it.each([
    [404, 'not found'],
    [409, 'conflict'],
  ])('reads the list again and says it was cleared first when the answer is a %i', async (status, code) => {
    const stub = stubFetch(onWrite(reply(status, code)));
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    await u.click(await screen.findByRole('button', { name: 'Clear the reason' }));
    expect(await screen.findByText('This reason was already cleared.')).toBeInTheDocument();
    await waitFor(() => expect(stub.requests.filter((request) => request === REASONS)).toHaveLength(2));
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });

  it('says to try again for a 429 and does not sign the person out', async () => {
    stubFetch(onWrite({ status: 429, headers: { 'Retry-After': '30' }, body: { error: 'rate limited' } }));
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    await u.click(await screen.findByRole('button', { name: 'Clear the reason' }));
    expect(await screen.findByText('Too many requests.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });

  it('sends one request for a double click', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    await u.dblClick(await screen.findByRole('button', { name: 'Clear the reason' }));
    await screen.findByText(`Cleared ${TLS}.`);
    expect(posts(stub)).toHaveLength(1);
  });

  it('is sent to sign in by a 401', async () => {
    stubFetch(onWrite(reply(401, 'unauthorized')));
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: `Clear ${TLS}` }));
    await u.click(await screen.findByRole('button', { name: 'Clear the reason' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
  });
});

describe('the allowlist', () => {
  it('shows the latest row of each host in words, with the opposite action', async () => {
    stubFetch();
    renderApp('/premises');
    const cards = await allowlist().findAllByRole('listitem');
    expect(cards.map((card) => within(card).getByRole('heading').textContent)).toEqual(['legacy.example.com', 'status.example.com']);
    const legacy = within(cards[0] as HTMLElement);
    expect(legacy.getByText('Withdrawn')).toBeInTheDocument();
    expect(legacy.getByRole('button', { name: 'Allow again legacy.example.com' })).toBeInTheDocument();
    const status = within(cards[1] as HTMLElement);
    expect(status.getByText('Allowed')).toBeInTheDocument();
    expect(status.getByRole('button', { name: 'Withdraw status.example.com' })).toBeInTheDocument();
    expect(allowlist().getAllByRole('listitem')).toHaveLength(2);
  });

  it('allows a host, lowercased, with a body that holds the host and the flag and nothing else', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await screen.findByRole('form', { name: 'Allow a host' });
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: '  New.Example.COM ' } });
    await u.click(screen.getByRole('button', { name: 'Allow the host' }));
    expect(await screen.findByText('Allowed new.example.com.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(posts(stub)[0]).toMatchObject({ url: '/v1/premise-hosts', body: '{"host":"new.example.com","allowed":true}', contentType: 'application/json' });
    expect(await allowlist().findByRole('heading', { name: 'new.example.com' })).toBeInTheDocument();
    expect(screen.getByLabelText('Host')).toHaveValue('');
    expect(stub.requests.filter((request) => request === HOSTS)).toHaveLength(2);
  });

  it('refuses a host the server would refuse before it sends anything, in words', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await screen.findByRole('form', { name: 'Allow a host' });
    await u.click(screen.getByRole('button', { name: 'Allow the host' }));
    expect(await screen.findByText('Give the host name a premise probe may dial.')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'https://status.example.com' } });
    expect(await screen.findByText(/with no scheme, port or path/, { selector: '.ip-field-error' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: '10.0.0.1' } });
    expect(await screen.findByText(/That is an address/)).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('withdraws a host with one request and says it stays listed', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: 'Withdraw status.example.com' }));
    expect(await screen.findByText('Withdrew status.example.com.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(posts(stub)[0]).toMatchObject({ url: '/v1/premise-hosts', body: '{"host":"status.example.com","allowed":false}' });
    expect(await screen.findByRole('button', { name: 'Allow again status.example.com' })).toBeInTheDocument();
    expect(allowlist().getAllByText('Withdrawn')).toHaveLength(2);
  });

  it('allows a withdrawn host again', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: 'Allow again legacy.example.com' }));
    expect(await screen.findByText('Allowed legacy.example.com.')).toBeInTheDocument();
    expect(posts(stub)[0]).toMatchObject({ body: '{"host":"legacy.example.com","allowed":true}' });
    expect(await screen.findByRole('button', { name: 'Withdraw legacy.example.com' })).toBeInTheDocument();
  });

  it('says in words that no role allows a change, at the row, and does not sign the person out', async () => {
    const stub = stubFetch(onWrite(reply(403, 'forbidden')));
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: 'Withdraw status.example.com' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Withdraw status.example.com' })).toBeEnabled();
    expect(stub.requests.filter((request) => request === HOSTS)).toHaveLength(1);
  });

  it('says in words what a 400 means for the host, and keeps what was typed', async () => {
    stubFetch(onWrite(reply(400, 'invalid query')));
    const u = user();
    renderApp('/premises');
    await screen.findByRole('form', { name: 'Allow a host' });
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'new.example.com' } });
    await u.click(screen.getByRole('button', { name: 'Allow the host' }));
    expect(await screen.findByText(/The server refused the host/)).toBeInTheDocument();
    expect(screen.getByLabelText('Host')).toHaveValue('new.example.com');
  });

  it('sends one request for a double click on the form button', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/premises');
    await screen.findByRole('form', { name: 'Allow a host' });
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'new.example.com' } });
    await u.dblClick(screen.getByRole('button', { name: 'Allow the host' }));
    await screen.findByText('Allowed new.example.com.');
    expect(posts(stub)).toHaveLength(1);
  });

  it('is sent to sign in by a 401 on a write', async () => {
    stubFetch(onWrite(reply(401, 'unauthorized')));
    const u = user();
    renderApp('/premises');
    await u.click(await screen.findByRole('button', { name: 'Withdraw status.example.com' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
  });

  it('offers the form when no host is allowed, so the first one can be added', async () => {
    stubFetch({ override: ({ url }) => (url.startsWith('/v1/premise-hosts') ? { status: 200, headers: {}, body: { premise_hosts: [] } } : undefined) });
    renderApp('/premises');
    expect(await screen.findByText('No host is allowed, so no probe can dial one.')).toBeInTheDocument();
    expect(screen.getByRole('form', { name: 'Allow a host' })).toBeInTheDocument();
  });

  it('shows no form and no action when the server refuses the read, and still shows the reasons', async () => {
    const stub = stubFetch({ override: ({ method, url }) => (method === 'GET' && url.startsWith('/v1/premise-hosts') ? reply(403, 'forbidden') : undefined) });
    renderApp('/premises');
    expect(await allowlist().findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Allow a host' })).not.toBeInTheDocument();
    expect(allowlist().queryByRole('button')).not.toBeInTheDocument();
    expect(await reasons().findByRole('button', { name: `Clear ${TLS}` })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    expect(stub.sent).toHaveLength(0);
  });
});

describe('the page of a signed-out person', () => {
  it('is the sign-in', async () => {
    stubFetch({ signedIn: false });
    renderApp('/premises');
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
  });
});
