import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { NOW, renderApp, stubFetch } from '../test/render';
import { refusalOf } from '../views/SignIn';
import { followSystemTheme } from '../theme';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('signing in', () => {
  it('asks a person who is not signed in to sign in, and offers each provider the server lists', async () => {
    stubFetch({ signedIn: false });
    renderApp('/decisions');
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Sign in with dex' })).toHaveAttribute('href', '/auth/login/dex');
    expect(screen.getByRole('link', { name: 'Sign in with GitHub' })).toHaveAttribute('href', '/auth/login/github');
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('says so when the server has no sign-in', async () => {
    stubFetch({ signedIn: false, override: ({ url }) => (url === '/auth/providers' ? { status: 401, headers: {}, body: { error: 'unauthorized' } } : undefined) });
    renderApp('/signin');
    expect(await screen.findByText('The sign-in options did not load. Reload the page to try again.')).toBeInTheDocument();

    vi.unstubAllGlobals();
    stubFetch({ signedIn: false, override: ({ url }) => (url === '/auth/providers' ? { status: 404, headers: {}, body: { error: 'not_found' } } : undefined) });
    renderApp('/signin');
    expect(await screen.findAllByText('Sign-in is not configured on this server.')).not.toHaveLength(0);
  });

  it('shows a signed-in person the sign-out, and signing out ends at the sign-in', async () => {
    const stub = stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions');
    await screen.findByRole('table', { name: 'Decisions in force' });
    await user.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to ipso' })).toBeInTheDocument();
    expect(stub.requests).toContain('POST /auth/logout');
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
  });

  it('keeps the sign-out when it fails, and says so', async () => {
    stubFetch({ override: ({ method, url }) => (method === 'POST' && url === '/auth/logout' ? { status: 429, headers: { 'Retry-After': '3' }, body: { error: 'rate_limited' } } : undefined) });
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions');
    await user.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('Sign-out failed. Try again.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
  });
});

describe('a refusal', () => {
  const refuse = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    stubFetch({ override: ({ url }) => (url.startsWith('/v1/decisions') ? { status, headers, body } : undefined) });

  it('is never a sign-out when the tenant is only busy', async () => {
    refuse(429, { error: 'rate limited' }, { 'Retry-After': '7' });
    renderApp('/decisions');
    expect(await screen.findByText('Too many requests.')).toBeInTheDocument();
    expect(screen.getByText('Try again in 7 seconds.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });

  it('says no role of the person allows the page', async () => {
    refuse(403, { error: 'forbidden' });
    renderApp('/decisions');
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.getByText('Ask a tenant admin for one.')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in to ipso' })).not.toBeInTheDocument();
  });

  it('says when the server did not answer, and tries again on request', async () => {
    let calls = 0;
    stubFetch({
      override: ({ url }) => {
        if (!url.startsWith('/v1/decisions/0194f2a0-0000-7000-8000-000000000101')) return undefined;
        calls += 1;
        if (calls === 1) throw new TypeError('Failed to fetch');
        return undefined;
      },
    });
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions/0194f2a0-0000-7000-8000-000000000101');
    expect(await screen.findByText('The server did not answer.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'Public ingress terminates TLS 1.2 or later' })).toBeInTheDocument();
  });

  it('turns the other codes into plain words', async () => {
    refuse(503, { error: 'timeout' });
    renderApp('/decisions');
    expect(await screen.findByText('The request took too long.')).toBeInTheDocument();
  });
});

describe('the shell', () => {
  it('has a way past the menu, a menu of the five views, and a page for a path that does not exist', async () => {
    stubFetch();
    renderApp('/nowhere');
    expect(await screen.findByRole('heading', { name: 'Not found' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Skip to content' })).toHaveAttribute('href', '#main');
    const menu = screen.getByRole('navigation', { name: 'Main' });
    expect(Array.from(menu.querySelectorAll('a')).map((a) => a.textContent)).toEqual(['Decisions', 'Scopes', 'Inbox', 'Waivers', 'Premises', 'Audit']);
  });

  it('sends the root to the registry', async () => {
    stubFetch();
    renderApp('/');
    expect(await screen.findByRole('heading', { name: 'Decisions' })).toBeInTheDocument();
  });

  it('blinks the cursor of the wordmark only while a request is in flight', async () => {
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const stub = stubFetch();
    const fetchNow = globalThis.fetch;
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      await held;
      return fetchNow(input, init);
    });
    void stub;
    renderApp('/decisions');
    await waitFor(() => expect(document.querySelector('.ip-wordmark-blink')).not.toBeNull());
    release();
    await screen.findByRole('table', { name: 'Decisions in force' });
    await waitFor(() => expect(document.querySelector('.ip-wordmark-blink')).toBeNull());
  });
});

describe('the theme', () => {
  function media(matches: boolean) {
    const listeners = new Set<() => void>();
    const query = {
      matches,
      addEventListener: (_: string, listener: () => void) => listeners.add(listener),
      removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
    } as unknown as MediaQueryList;
    return { query, change: (next: boolean) => { (query as { matches: boolean }).matches = next; listeners.forEach((listener) => listener()); }, listeners };
  }

  it('follows the system, light or dark, and stops when told', () => {
    const root = document.createElement('div');
    const system = media(true);
    const stop = followSystemTheme(root, system.query);
    expect(root.dataset.theme).toBe('dark');
    system.change(false);
    expect(root.dataset.theme).toBe('light');
    stop();
    expect(system.listeners.size).toBe(0);
    system.change(true);
    expect(root.dataset.theme).toBe('light');
  });
});

describe('the invitations entry of the menu', () => {
  const current = (status: number, body: unknown) => ({ override: ({ url }: { url: string }) => (url.startsWith('/v1/invitations') ? { status, headers: {}, body } : undefined) });

  it('is there when the server answers the read, even with none open', async () => {
    stubFetch();
    renderApp('/decisions');
    expect(await screen.findByRole('link', { name: 'Invitations' })).toHaveAttribute('href', '/invitations');
  });

  it('is left out when the server refuses the read, and the app copies no policy', async () => {
    const stub = stubFetch(current(403, { error: 'forbidden' }));
    renderApp('/decisions');
    await waitFor(() => expect(stub.requests).toContain('GET /v1/invitations?limit=1'));
    await screen.findByRole('link', { name: 'Decisions' });
    expect(screen.queryByRole('link', { name: 'Invitations' })).not.toBeInTheDocument();
  });

  it('stays when the read fails for a reason that is not a refusal', async () => {
    const stub = stubFetch(current(503, { error: 'timeout' }));
    renderApp('/decisions');
    await waitFor(() => expect(stub.requests).toContain('GET /v1/invitations?limit=1'));
    expect(await screen.findByRole('link', { name: 'Invitations' })).toBeInTheDocument();
  });

  it('is left out when no one is signed in', async () => {
    const stub = stubFetch({ signedIn: false });
    renderApp('/decisions');
    await screen.findByRole('heading', { name: 'Sign in to ipso' });
    expect(screen.queryByRole('link', { name: 'Invitations' })).not.toBeInTheDocument();
    expect(stub.requests.some((request) => request.startsWith('GET /v1/invitations'))).toBe(false);
  });

  it('follows its own read: an export that is refused does not hide it', async () => {
    stubFetch({ override: ({ url }) => (url === '/v1/exports/current' ? { status: 403, headers: {}, body: { error: 'forbidden' } } : undefined) });
    renderApp('/decisions');
    expect(await screen.findByRole('link', { name: 'Invitations' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Export' })).not.toBeInTheDocument();
  });
});

describe('the export entry of the menu', () => {
  const current = (status: number, body: unknown) => ({ override: ({ url }: { url: string }) => (url === '/v1/exports/current' ? { status, headers: {}, body } : undefined) });

  it('is there when the server answers the export read, even with none held', async () => {
    stubFetch();
    renderApp('/decisions');
    expect(await screen.findByRole('link', { name: 'Export' })).toHaveAttribute('href', '/export');
  });

  it('is left out when the server refuses the read, and the app copies no policy', async () => {
    const stub = stubFetch(current(403, { error: 'forbidden' }));
    renderApp('/decisions');
    await waitFor(() => expect(stub.requests).toContain('GET /v1/exports/current'));
    await screen.findByRole('link', { name: 'Decisions' });
    expect(screen.queryByRole('link', { name: 'Export' })).not.toBeInTheDocument();
  });

  it('stays when the read fails for a reason that is not a refusal', async () => {
    const stub = stubFetch(current(503, { error: 'timeout' }));
    renderApp('/decisions');
    await waitFor(() => expect(stub.requests).toContain('GET /v1/exports/current'));
    expect(await screen.findByRole('link', { name: 'Export' })).toBeInTheDocument();
  });

  it('is left out when no one is signed in', async () => {
    const stub = stubFetch({ signedIn: false });
    renderApp('/decisions');
    await screen.findByRole('heading', { name: 'Sign in to ipso' });
    expect(screen.queryByRole('link', { name: 'Export' })).not.toBeInTheDocument();
    expect(stub.requests).not.toContain('GET /v1/exports/current');
  });
});

const REFUSALS = {
  unknown_login: 'This account is not a member of this organization. Give an administrator the issuer and the subject below so they can invite you or bind the login.',
  unknown_invitation: 'This invitation was already used, was withdrawn, or has expired. Ask the person who invited you for a new one.',
  invalid_login: 'The sign-in did not finish. Start again.',
  login_refused: 'The sign-in was cancelled or refused. Start again if you still want to sign in.',
  forbidden: 'This login belongs to an agent. Sign in with a person account.',
  rate_limited: 'Too many tries. Wait a moment and try again.',
  internal: 'The sign-in could not be completed. Try again in a moment.',
  not_found: 'This sign-in provider is not configured.',
};

function openSignIn(hash: string) {
  window.history.replaceState(null, '', `/signin${hash}`);
}

describe('a refused sign-in', () => {
  afterEach(() => {
    window.history.replaceState(null, '', '/');
  });

  it('says in words what to do for each code, and never shows the code', async () => {
    for (const [code, words] of Object.entries(REFUSALS)) {
      openSignIn(`#code=${code}`);
      stubFetch({ signedIn: false });
      const view = renderApp('/signin');
      const alert = await screen.findByRole('alert');
      expect(alert).toHaveTextContent(words);
      expect(alert).not.toHaveTextContent(code);
      expect(window.location.hash).toBe('');
      expect(await screen.findByRole('link', { name: 'Sign in with dex' })).toHaveAttribute('href', '/auth/login/dex');
      view.unmount();
      vi.unstubAllGlobals();
    }
  });

  it('shows the issuer and the subject only for an unknown login, as text', async () => {
    openSignIn('#code=unknown_login&issuer=javascript%3Aalert(1)&subject=person-9');
    stubFetch({ signedIn: false });
    renderApp('/signin');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Issuer:');
    expect(alert).toHaveTextContent('javascript:alert(1)');
    expect(alert).toHaveTextContent('Subject:');
    expect(alert).toHaveTextContent('person-9');
    expect(screen.getByText('javascript:alert(1)').closest('a')).toBeNull();
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(window.location.hash).toBe('');
    expect(window.location.href).not.toContain('person-9');
  });

  it('does not show an issuer that arrived with another code', async () => {
    openSignIn('#code=login_refused&issuer=https%3A%2F%2Fidp.test&subject=person-9&error_description=the%20user%20said%20no');
    stubFetch({ signedIn: false });
    renderApp('/signin');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(REFUSALS.login_refused);
    expect(alert).not.toHaveTextContent('idp.test');
    expect(alert).not.toHaveTextContent('person-9');
    expect(alert).not.toHaveTextContent('the user said no');
    expect(alert).not.toHaveTextContent('login_refused');
  });

  it('treats a code outside the set as a sign-in that did not finish, and shows no extra value', async () => {
    openSignIn('#code=access_denied&issuer=https%3A%2F%2Fidp.test&subject=person-9');
    stubFetch({ signedIn: false });
    renderApp('/signin');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(REFUSALS.invalid_login);
    expect(alert).not.toHaveTextContent('access_denied');
    expect(alert).not.toHaveTextContent('idp.test');
    expect(alert).not.toHaveTextContent('person-9');
  });

  it('omits an issuer or subject that is too long or has a control character', async () => {
    const long = 'Z'.repeat(2049);
    openSignIn(`#code=unknown_login&issuer=${encodeURIComponent(long)}&subject=${encodeURIComponent('ok-subject\nno')}`);
    stubFetch({ signedIn: false });
    renderApp('/signin');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(REFUSALS.unknown_login);
    expect(alert).not.toHaveTextContent(long);
    expect(alert).not.toHaveTextContent('ok-subject');
    expect(alert).not.toHaveTextContent('Issuer:');
    expect(alert).not.toHaveTextContent('Subject:');
  });

  it('reads the fragment the page reads', () => {
    expect(refusalOf('')).toBeNull();
    expect(refusalOf('#')).toBeNull();
    expect(refusalOf('#code=unknown_login&issuer=https://idp.test&subject=person-9')).toEqual({
      words: REFUSALS.unknown_login,
      issuer: 'https://idp.test',
      subject: 'person-9',
    });
    expect(refusalOf('#foo=1')).toEqual({ words: REFUSALS.invalid_login, issuer: null, subject: null });
  });
});
