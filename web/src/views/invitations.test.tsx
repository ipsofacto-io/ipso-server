import { act, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FixtureReply } from '../../fixtures/server.ts';
import { NOW, renderApp, stubFetch } from '../test/render';

const LINK = /^https:\/\/ipso\.example\.test\/invitation#[A-Za-z0-9_-]{43}$/;
const LIST = 'GET /v1/invitations?limit=25';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  window.sessionStorage.clear();
  document.title = '';
});

const reply = (status: number, body: unknown, headers: Record<string, string> = {}): FixtureReply => ({ status, headers, body });
const refuse = (method: string, status: number, error: string) => ({
  override: (request: { method: string }) => (request.method === method ? reply(status, { error }) : undefined),
});
const user = () => userEvent.setup({ advanceTimers: () => {} });
const sent = (stub: ReturnType<typeof stubFetch>, method: string) => stub.sent.filter((request) => request.method === method);
const open = () => within(screen.getByRole('region', { name: 'Open invitations' }));

/** Sets a field at once: typing 201 characters one by one adds nothing to what is checked, and a tab cannot be typed. */
const setValue = (field: HTMLElement, value: string) =>
  act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });

async function invite(u: ReturnType<typeof user>, name: string, role?: string) {
  await u.type(await screen.findByLabelText('Name'), name);
  if (role) await u.selectOptions(screen.getByLabelText('Role'), role);
  await u.click(screen.getByRole('button', { name: 'Invite the person' }));
}

describe('the invitations screen', () => {
  it('shows the form and says that no invitation is open', async () => {
    stubFetch();
    renderApp('/invitations');
    expect(await screen.findByRole('heading', { name: 'Invitations', level: 1 })).toBeInTheDocument();
    expect(await screen.findByText('No invitation is open.')).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toHaveAttribute('autocomplete', 'off');
    expect(screen.getByLabelText('Role')).toHaveValue('viewer');
  });

  it('offers the six roles a person may hold and never agent', async () => {
    stubFetch();
    renderApp('/invitations');
    const options = within(await screen.findByLabelText('Role')).getAllByRole('option');
    expect(options.map((option) => option.getAttribute('value'))).toEqual(['viewer', 'contributor', 'decision-owner', 'approver', 'admin', 'auditor']);
    expect(screen.queryByRole('option', { name: /agent/ })).not.toBeInTheDocument();
  });

  it('sends the name and the role and nothing else, and shows the link once', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, '  Ada Lovelace  ', 'auditor');
    expect(await screen.findByRole('heading', { name: 'Link for Ada Lovelace' })).toBeInTheDocument();
    expect(sent(stub, 'POST')).toHaveLength(1);
    expect(sent(stub, 'POST')[0]).toMatchObject({ url: '/v1/invitations', contentType: 'application/json' });
    expect(JSON.parse(sent(stub, 'POST')[0]?.body ?? '')).toEqual({ name: 'Ada Lovelace', role: 'auditor' });
    const field = screen.getByLabelText('Invitation link');
    expect((field as HTMLInputElement).value).toMatch(LINK);
    expect(field).toHaveAttribute('readonly');
    expect(screen.getByText('This link is shown once.')).toBeInTheDocument();
    expect(screen.getByText(/The server keeps no copy/)).toBeInTheDocument();
    expect(screen.getByText(/Whoever opens it and signs in first becomes Ada Lovelace with the role auditor/)).toBeInTheDocument();
    // The form is ready for the next person.
    expect(screen.getByLabelText('Name')).toHaveValue('');
  });

  it('never makes the link an anchor and never keeps it in the storage of the browser', async () => {
    stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    const field = (await screen.findByLabelText('Invitation link')) as HTMLInputElement;
    expect(document.querySelectorAll('a[href*="invitation#"]')).toHaveLength(0);
    const token = field.value.split('#')[1] ?? '';
    expect(token).toHaveLength(43);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(window.location.hash).toBe('');
    expect(document.title).not.toContain(token);
  });

  it('lists the open invitation without a token once the list is read again', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada', 'approver');
    const card = within(await open().findByRole('listitem'));
    expect(card.getByRole('heading', { name: 'Ada' })).toBeInTheDocument();
    expect(card.getByText('approver')).toBeInTheDocument();
    expect(card.getByText('Expires in 7 days')).toBeInTheDocument();
    expect(card.getByText('2026-11-07 12:00 UTC')).toBeInTheDocument();
    expect(card.queryByText(/invitation#/)).not.toBeInTheDocument();
    expect(card.queryByRole('textbox')).not.toBeInTheDocument();
    expect(stub.requests.filter((request) => request === LIST)).toHaveLength(2);
  });

  it('shows the name of an invitation as text, never as markup', async () => {
    const markup = '<img src=x onerror="alert(1)">';
    stubFetch({
      override: ({ method }) =>
        method === 'GET'
          ? reply(200, {
              invitations: [
                {
                  id: '0194f2a0-0000-7000-8000-000000001001',
                  name: markup,
                  role: 'viewer',
                  created_by: '0194f2a0-0000-7000-8000-0000000000a1',
                  created_at: '2026-11-07T11:00:00Z',
                  expires_at: '2026-11-14T11:00:00Z',
                },
              ],
            })
          : undefined,
    });
    renderApp('/invitations');
    expect(await open().findByRole('heading', { name: markup })).toBeInTheDocument();
    expect(document.querySelector('main img')).toBeNull();
    expect(document.querySelector('[onerror]')).toBeNull();
  });

  it('tells two people of one name and role apart by the end of the id', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    await open().findByRole('listitem');
    await invite(u, 'Ada');
    await within(open().getAllByRole('listitem')[1] as HTMLElement).findByRole('heading', { name: 'Ada' });
    expect(screen.getByRole('button', { name: 'Revoke the invitation of Ada (viewer, 00001001)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Revoke the invitation of Ada (viewer, 00001002)' })).toBeInTheDocument();
    expect(stub.requests.filter((request) => request.startsWith('POST'))).toHaveLength(2);
  });

  it('copies the link', async () => {
    stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    const field = (await screen.findByLabelText('Invitation link')) as HTMLInputElement;
    await u.click(screen.getByRole('button', { name: 'Copy the link' }));
    expect(await screen.findByText('Copied.')).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(field.value);
  });

  it('says so when the browser does not allow the copy', async () => {
    stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    await screen.findByLabelText('Invitation link');
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    await u.click(screen.getByRole('button', { name: 'Copy the link' }));
    expect(await screen.findByText(/did not allow the copy/)).toBeInTheDocument();
    expect(screen.queryByText('Copied.')).not.toBeInTheDocument();
  });

  it('hides the link, and a new invitation replaces it', async () => {
    stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    const first = ((await screen.findByLabelText('Invitation link')) as HTMLInputElement).value;
    await u.click(screen.getByRole('button', { name: 'Hide the link' }));
    expect(screen.queryByLabelText('Invitation link')).not.toBeInTheDocument();
    await invite(u, 'Grace');
    const second = ((await screen.findByLabelText('Invitation link')) as HTMLInputElement).value;
    expect(screen.getByRole('heading', { name: 'Link for Grace' })).toBeInTheDocument();
    expect(second).not.toBe(first);
  });
});

describe('the checks before the request', () => {
  it('asks for a name before it sends anything', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    await u.click(await screen.findByRole('button', { name: 'Invite the person' }));
    expect(await screen.findByText('Give the name of the person you are inviting.')).toBeInTheDocument();
    expect(sent(stub, 'POST')).toHaveLength(0);
    await u.type(screen.getByLabelText('Name'), '   ');
    await u.click(screen.getByRole('button', { name: 'Invite the person' }));
    expect(screen.getByText('Give the name of the person you are inviting.')).toBeInTheDocument();
    expect(sent(stub, 'POST')).toHaveLength(0);
  });

  it('refuses a name over 200 characters and one with a control character', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    const name = await screen.findByLabelText('Name');
    await setValue(name, 'a'.repeat(201));
    await u.click(screen.getByRole('button', { name: 'Invite the person' }));
    expect(await screen.findByText('A name is at most 200 characters.')).toBeInTheDocument();
    await setValue(name, 'Ada\tLovelace');
    expect(await screen.findByText(/no control character/)).toBeInTheDocument();
    expect(sent(stub, 'POST')).toHaveLength(0);
  });

  it('accepts a name of exactly 200 characters', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    const name = await screen.findByLabelText('Name');
    await setValue(name, 'a'.repeat(200));
    await u.click(screen.getByRole('button', { name: 'Invite the person' }));
    expect(await screen.findByLabelText('Invitation link')).toBeInTheDocument();
    expect(sent(stub, 'POST')).toHaveLength(1);
  });
});

describe('what the server refuses', () => {
  it('says in words that a 409 on create has two causes, and shows no link', async () => {
    const u = user();
    stubFetch(refuse('POST', 409, 'conflict'));
    renderApp('/invitations');
    await invite(u, 'Ada');
    expect(await screen.findByText('This conflicts with what is recorded.')).toBeInTheDocument();
    expect(screen.getByText(/Browser sign-in is not set up on this server/)).toBeInTheDocument();
    expect(screen.getByText(/already holds 1000 open invitations/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Invitation link')).not.toBeInTheDocument();
    // The form stays, with what the person typed, so they can try again.
    expect(screen.getByLabelText('Name')).toHaveValue('Ada');
  });

  it('says in words that a 403 on create means no role allows it, and signs nobody out', async () => {
    const u = user();
    stubFetch(refuse('POST', 403, 'forbidden'));
    renderApp('/invitations');
    await invite(u, 'Ada');
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toBeInTheDocument();
  });

  it('says in words that a 400 on create is a refused value', async () => {
    const u = user();
    stubFetch(refuse('POST', 400, 'invalid query'));
    renderApp('/invitations');
    await invite(u, 'Ada');
    expect(await screen.findByText('The server refused a value.')).toBeInTheDocument();
    expect(screen.getByText(/refused the name or the role/)).toBeInTheDocument();
  });

  it('says that a 429 only means to try again', async () => {
    const u = user();
    stubFetch({ override: ({ method }) => (method === 'POST' ? reply(429, { error: 'rate limited' }, { 'Retry-After': '9' }) : undefined) });
    renderApp('/invitations');
    await invite(u, 'Ada');
    expect(await screen.findByText('Too many requests.')).toBeInTheDocument();
    expect(screen.getByText('Try again in 9 seconds.')).toBeInTheDocument();
  });

  it('shows the refusal and nothing else to a person without the role, and leaves the menu entry out', async () => {
    const stub = stubFetch(refuse('GET', 403, 'forbidden'));
    renderApp('/invitations');
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Invite the person' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    await screen.findByRole('link', { name: 'Decisions' });
    expect(screen.queryByRole('link', { name: 'Invitations' })).not.toBeInTheDocument();
    expect(stub.requests).toContain(LIST);
  });

  it('keeps the menu entry when the read fails for a reason that is not a refusal', async () => {
    stubFetch(refuse('GET', 503, 'timeout'));
    renderApp('/invitations');
    expect(await screen.findByText('The request took too long.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Invitations' })).toBeInTheDocument();
  });
});

describe('the menu entry and the page share one read', () => {
  it('reads the invitations once on the page, which tells the menu', async () => {
    const stub = stubFetch();
    renderApp('/invitations');
    expect(await screen.findByLabelText('Name')).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Invitations' })).toHaveAttribute('href', '/invitations');
    expect(stub.requests.filter((request) => request.startsWith('GET /v1/invitations'))).toEqual([LIST]);
  });
});

describe('revoking an invitation', () => {
  it('asks first, sends one request, and the invitation leaves the list', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada', 'contributor');
    await open().findByRole('listitem');
    await u.click(await screen.findByRole('button', { name: /^Revoke the invitation of Ada \(contributor, 00001001\)$/ }));
    expect(screen.getByText(/Its link stops working at once/)).toBeInTheDocument();
    expect(stub.requests.filter((request) => request.startsWith('DELETE'))).toHaveLength(0);
    await u.click(screen.getByRole('button', { name: 'Revoke the invitation' }));
    expect(await screen.findByText(/^Revoked the invitation of Ada/)).toBeInTheDocument();
    expect(await screen.findByText('No invitation is open.')).toBeInTheDocument();
    expect(stub.requests.filter((request) => request.startsWith('DELETE'))).toEqual([expect.stringMatching(/^DELETE \/v1\/invitations\/0194f2a0-/)]);
  });

  it('sends nothing when the person cancels', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    await open().findByRole('listitem');
    await u.click(await screen.findByRole('button', { name: /^Revoke the invitation of Ada/ }));
    await u.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(stub.requests.filter((request) => request.startsWith('DELETE'))).toHaveLength(0);
    expect(await screen.findByRole('button', { name: /^Revoke the invitation of Ada/ })).toBeInTheDocument();
  });

  it('says that an invitation that is already gone is gone, and reads the list again', async () => {
    const stub = stubFetch(refuse('DELETE', 404, 'not found'));
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    await open().findByRole('listitem');
    const before = stub.requests.filter((request) => request === LIST).length;
    await u.click(await screen.findByRole('button', { name: /^Revoke the invitation of Ada/ }));
    await u.click(screen.getByRole('button', { name: 'Revoke the invitation' }));
    expect(await screen.findByText('This invitation is already gone.')).toBeInTheDocument();
    expect(screen.getByText(/It was used, revoked or has expired/)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
    expect(stub.requests.filter((request) => request === LIST).length).toBe(before + 1);
  });

  it('says in words that a 403 means no role allows it, and signs nobody out', async () => {
    stubFetch(refuse('DELETE', 403, 'forbidden'));
    const u = user();
    renderApp('/invitations');
    await invite(u, 'Ada');
    await open().findByRole('listitem');
    await u.click(await screen.findByRole('button', { name: /^Revoke the invitation of Ada/ }));
    await u.click(screen.getByRole('button', { name: 'Revoke the invitation' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });
});

describe('without a session', () => {
  it('sends the person to the sign-in', async () => {
    stubFetch({ signedIn: false });
    renderApp('/invitations');
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
  });
});
