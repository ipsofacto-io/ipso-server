import { act, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { OPEN_INVITATION, type FixtureReply } from '../../fixtures/server.ts';
import { goTo } from '../lib/navigate';
import { NOW, renderApp, stubFetch } from '../test/render';
import { tokenOf } from './Invitation';

vi.mock('../lib/navigate', () => ({ goTo: vi.fn() }));

const reply = (status: number, body: unknown, headers: Record<string, string> = {}): FixtureReply => ({ status, headers, body });
const user = () => userEvent.setup({ advanceTimers: () => {} });
const posts = (stub: ReturnType<typeof stubFetch>) => stub.sent.filter((sent) => sent.method === 'POST');

const assign = vi.mocked(goTo);

/** Opens the page the way a link does: the token is in the fragment. */
function open(hash: string) {
  window.history.replaceState(null, '', `/invitation${hash}`);
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  assign.mockClear();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.history.replaceState(null, '', '/');
  document.title = '';
});

describe('reading the token of a link', () => {
  it('takes exactly 43 characters of unpadded base64url, with or without the hash sign', () => {
    expect(tokenOf(`#${OPEN_INVITATION}`)).toBe(OPEN_INVITATION);
    expect(tokenOf(OPEN_INVITATION)).toBe(OPEN_INVITATION);
    for (const bad of ['', '#', '#short', `#${OPEN_INVITATION}x`, `#${'!'.repeat(43)}`, `#${'o'.repeat(42)}=`, `#token=${OPEN_INVITATION}`]) {
      expect(tokenOf(bad)).toBeNull();
    }
  });
});

describe('the invitation page', () => {
  it('removes the token from the address at once and keeps it out of every request but the one that starts the sign-in', async () => {
    open(`#${OPEN_INVITATION}`);
    const stub = stubFetch({ signedIn: false });
    renderApp('/invitation');
    expect(await screen.findByRole('heading', { name: 'You are invited to ipso' })).toBeInTheDocument();
    expect(window.location.hash).toBe('');
    expect(window.location.href).not.toContain(OPEN_INVITATION);
    expect(stub.requests.every((request) => !request.includes(OPEN_INVITATION))).toBe(true);
    expect(posts(stub)).toHaveLength(0);
  });

  it('offers each provider the server lists and sends the token in a JSON body, then goes where the server says', async () => {
    open(`#${OPEN_INVITATION}`);
    const stub = stubFetch({ signedIn: false });
    renderApp('/invitation');
    const button = await screen.findByRole('button', { name: 'Sign in with dex' });
    expect(screen.getByRole('button', { name: 'Sign in with GitHub' })).toBeInTheDocument();
    await user().click(button);

    expect(posts(stub)).toEqual([
      { method: 'POST', url: '/auth/invitation/dex', body: JSON.stringify({ token: OPEN_INVITATION }), contentType: 'application/json' },
    ]);
    await act(async () => {});
    expect(assign).toHaveBeenCalledWith(new URL('/auth/login/dex', window.location.origin).href);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('gives the buttons back when the page is restored from the back/forward cache after the sign-in began', async () => {
    open(`#${OPEN_INVITATION}`);
    stubFetch({ signedIn: false });
    renderApp('/invitation');
    await user().click(await screen.findByRole('button', { name: 'Sign in with dex' }));
    expect(await screen.findByRole('button', { name: 'Opening the sign-in...' })).toBeDisabled();
    act(() => {
      window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true }));
    });
    expect(await screen.findByRole('button', { name: 'Sign in with dex' })).toBeEnabled();
    // A page that was not restored keeps its state.
    await user().click(screen.getByRole('button', { name: 'Sign in with dex' }));
    act(() => {
      window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: false }));
    });
    expect(screen.getByRole('button', { name: 'Opening the sign-in...' })).toBeDisabled();
  });

  it('asks for the link again when there is no token, or one that does not read, and starts nothing', async () => {
    for (const hash of ['', '#abc', `#${OPEN_INVITATION}extra`]) {
      open(hash);
      const stub = stubFetch({ signedIn: false });
      const { unmount } = renderApp('/invitation');
      expect(await screen.findByText(/This invitation link is not complete/)).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Sign in with/ })).not.toBeInTheDocument();
      expect(posts(stub)).toHaveLength(0);
      unmount();
      vi.unstubAllGlobals();
    }
  });

  it('says in words that an invitation that is used, withdrawn, expired or never made cannot be used', async () => {
    open(`#${'x'.repeat(43)}`);
    stubFetch({ signedIn: false });
    renderApp('/invitation');
    await user().click(await screen.findByRole('button', { name: 'Sign in with dex' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('already used, was withdrawn, or has expired');
    expect(screen.queryByText('unknown_invitation')).not.toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
    // The buttons are back, so a person can try another provider or ask for a new link.
    expect(screen.getByRole('button', { name: 'Sign in with dex' })).toBeEnabled();
  });

  it('says to wait on a 429, with the seconds the server named, and does not go on', async () => {
    open(`#${OPEN_INVITATION}`);
    stubFetch({
      signedIn: false,
      override: ({ method, url }) => (method === 'POST' && url.startsWith('/auth/invitation/') ? reply(429, { error: 'rate_limited' }, { 'Retry-After': '7' }) : undefined),
    });
    renderApp('/invitation');
    await user().click(await screen.findByRole('button', { name: 'Sign in with dex' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 7 seconds.');
    expect(assign).not.toHaveBeenCalled();
  });

  it('says when the server cannot be reached or fails, and never shows the code', async () => {
    open(`#${OPEN_INVITATION}`);
    stubFetch({
      signedIn: false,
      override: ({ method, url }) => (method === 'POST' && url.startsWith('/auth/invitation/') ? reply(500, { error: 'internal' }) : undefined),
    });
    renderApp('/invitation');
    await user().click(await screen.findByRole('button', { name: 'Sign in with dex' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be started');
    expect(screen.queryByText('internal')).not.toBeInTheDocument();
  });

  it('refuses to go anywhere that is not http or https', async () => {
    open(`#${OPEN_INVITATION}`);
    stubFetch({
      signedIn: false,
      override: ({ method, url }) => (method === 'POST' && url.startsWith('/auth/invitation/') ? reply(200, { location: 'javascript:alert(1)' }) : undefined),
    });
    renderApp('/invitation');
    await user().click(await screen.findByRole('button', { name: 'Sign in with dex' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it('does not ask a person who is not signed in to sign in first, and says so when the server has no sign-in', async () => {
    open(`#${OPEN_INVITATION}`);
    stubFetch({ signedIn: false, override: ({ url }) => (url === '/auth/providers' ? reply(404, { error: 'not_found' }) : undefined) });
    renderApp('/invitation');
    expect(await screen.findByText('Sign-in is not configured on this server.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });
});
