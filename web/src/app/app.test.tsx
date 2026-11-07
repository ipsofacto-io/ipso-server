import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { NOW, renderApp, stubFetch } from '../test/render';
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

  it('says a sign-in is not bound to a person', async () => {
    refuse(403, { error: 'forbidden' });
    renderApp('/decisions');
    expect(await screen.findByText('Your sign-in is not bound to a person of this tenant.')).toBeInTheDocument();
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
    expect(Array.from(menu.querySelectorAll('a')).map((a) => a.textContent)).toEqual(['Decisions', 'Scopes', 'Inbox', 'Waivers', 'Audit']);
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
