import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { FIXTURE_TENANTS } from '../../fixtures/server.ts';
import { goTo } from '../lib/navigate';
import { renderApp, stubFetch } from '../test/render';
import { safeChoiceLocation } from './ChooseTenant';

vi.mock('../lib/navigate', () => ({ goTo: vi.fn() }));

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  document.title = '';
});

describe('safeChoiceLocation', () => {
  it('allows only root for browser sign-in', () => {
    expect(safeChoiceLocation('/', 'browser')).toBe('/');
    expect(safeChoiceLocation('https://evil.example/', 'browser')).toBeNull();
    expect(safeChoiceLocation('http://127.0.0.1:54321/callback?code=1', 'browser')).toBeNull();
    expect(safeChoiceLocation('//evil.example/', 'browser')).toBeNull();
    expect(safeChoiceLocation('/decisions', 'browser')).toBeNull();
  });

  it('allows only IPv4 loopback callback URLs for CLI sign-in', () => {
    expect(safeChoiceLocation('http://127.0.0.1:54321/callback?code=abc&state=xyz', 'cli')).toBe(
      'http://127.0.0.1:54321/callback?code=abc&state=xyz',
    );
    expect(safeChoiceLocation('http://127.0.0.1/callback?code=abc', 'cli')).toBeNull();
    expect(safeChoiceLocation('https://127.0.0.1:54321/callback?code=abc', 'cli')).toBeNull();
    expect(safeChoiceLocation('http://localhost:54321/callback?code=abc', 'cli')).toBeNull();
    expect(safeChoiceLocation('http://127.0.0.1:54321/other?code=abc', 'cli')).toBeNull();
    expect(safeChoiceLocation('javascript:alert(1)', 'cli')).toBeNull();
    expect(safeChoiceLocation('/', 'cli')).toBeNull();
  });
});

describe('the tenant choice route (/signin/tenant)', () => {
  it('lists the pending browser tenants, posts the chosen tenant_id, and navigates to /', async () => {
    const stub = stubFetch({
      signedIn: false,
      override: ({ method, url }) => {
        if (method === 'GET' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { tenants: FIXTURE_TENANTS, flow: 'browser' } };
        }
        if (method === 'POST' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { location: '/' } };
        }
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderApp('/signin/tenant');

    const betaBtn = await screen.findByRole('button', { name: 'Beta Platform' });
    expect(screen.getByRole('button', { name: 'Acme Europe' })).toBeInTheDocument();
    await user.click(betaBtn);

    await waitFor(() => expect(goTo).toHaveBeenCalledWith('/'));
    expect(stub.sent).toEqual([
      {
        method: 'POST',
        url: '/auth/tenants',
        body: JSON.stringify({ tenant_id: FIXTURE_TENANTS[1].id }),
        contentType: 'application/json',
      },
    ]);
  });

  it('shows CLI copy and navigates to the validated loopback callback URL', async () => {
    const loopback = 'http://127.0.0.1:54321/callback?code=one-time&state=s1';
    stubFetch({
      signedIn: false,
      override: ({ method, url }) => {
        if (method === 'GET' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { tenants: FIXTURE_TENANTS, flow: 'cli' } };
        }
        if (method === 'POST' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { location: loopback } };
        }
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderApp('/signin/tenant');

    expect(await screen.findByText(/sign in to with the ipso CLI/i)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Acme Europe' }));
    await waitFor(() => expect(goTo).toHaveBeenCalledWith(loopback));
  });

  it('disambiguates duplicate tenant names with their tenant UUID', async () => {
    const dupes = [
      { id: '0194f2a0-0000-7000-8000-000000000001', name: 'Acme' },
      { id: '0194f2b0-0000-7000-8000-000000000002', name: 'Acme' },
    ];
    stubFetch({
      signedIn: false,
      override: ({ method, url }) =>
        method === 'GET' && url === '/auth/tenants' ? { status: 200, headers: {}, body: { tenants: dupes, flow: 'browser' } } : undefined,
    });
    renderApp('/signin/tenant');
    expect(await screen.findByRole('button', { name: /Acme.*0194f2a0/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Acme.*0194f2b0/ })).toBeInTheDocument();
  });

  it('cancels the pending choice via DELETE /auth/tenants and returns to /signin', async () => {
    const stub = stubFetch({
      signedIn: false,
      override: ({ method, url }) => {
        if (method === 'GET' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { tenants: FIXTURE_TENANTS, flow: 'browser' } };
        }
        if (method === 'DELETE' && url === '/auth/tenants') {
          return { status: 204, headers: {} };
        }
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderApp('/signin/tenant');

    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    await screen.findByRole('heading', { level: 2, name: 'Sign in to ipso' });
    expect(stub.requests).toContain('DELETE /auth/tenants');
  });

  it('shows clear prose when the choice expired, is forbidden, or is rate-limited, without leaking raw codes', async () => {
    stubFetch({
      signedIn: false,
      override: ({ method, url }) =>
        method === 'GET' && url === '/auth/tenants' ? { status: 401, headers: {}, body: { error: 'invalid_login' } } : undefined,
    });
    renderApp('/signin/tenant');
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('This sign-in choice has expired or is no longer available. Start sign-in again.');
    expect(alert.textContent).not.toContain('invalid_login');
  });

  it('resets submitting state on bfcache pageshow restore', async () => {
    stubFetch({
      signedIn: false,
      override: ({ method, url }) => {
        if (method === 'GET' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { tenants: FIXTURE_TENANTS, flow: 'browser' } };
        }
        if (method === 'POST' && url === '/auth/tenants') {
          return { status: 200, headers: {}, body: { location: '/' } };
        }
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderApp('/signin/tenant');
    const btn = await screen.findByRole('button', { name: 'Acme Europe' });
    await user.click(btn);
    expect(btn).toBeDisabled();

    const event = new Event('pageshow') as PageTransitionEvent;
    Object.defineProperty(event, 'persisted', { value: true });
    fireEvent(window, event);
    await waitFor(() => expect(btn).not.toBeDisabled());
  });
});
