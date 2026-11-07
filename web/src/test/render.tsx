import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { vi } from 'vitest';

import { respond, SESSION_COOKIE, type FixtureReply } from '../../fixtures/server.ts';
import { AppRoutes } from '../App';
import { AppProvider } from '../app/AppContext';

/** The day the tests run on, so a waiver's deadline reads the same every time. */
export const NOW = new Date('2026-11-07T12:00:00Z');

export interface Stub {
  /** Every request the app made, as "METHOD /path?query". */
  requests: string[];
}

type Override = (request: { method: string; url: string }) => FixtureReply | undefined;

/** Answers fetch from the fixture server. `override` can answer first, to make a route fail or page. */
export function stubFetch({ signedIn = true, override }: { signedIn?: boolean; override?: Override } = {}): Stub {
  const requests: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      requests.push(`${method} ${url}`);
      const reply = override?.({ method, url }) ?? respond({ method, url, cookie: signedIn ? `${SESSION_COOKIE}=1` : '' }, NOW);
      const status = reply.status;
      const body = status === 204 || status === 303 ? null : JSON.stringify(reply.body ?? null);
      return new Response(body, { status, headers: { 'Content-Type': 'application/json', ...reply.headers } });
    }),
  );
  return { requests };
}

export function renderApp(path: string) {
  return render(
    <AppProvider>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </AppProvider>,
  );
}
