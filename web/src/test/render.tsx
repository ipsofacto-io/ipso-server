import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { vi } from 'vitest';

import { newFixtureState, respond, SESSION_COOKIE, type FixtureReply } from '../../fixtures/server.ts';
import { AppRoutes } from '../App';
import { AppProvider } from '../app/AppContext';

/** The day the tests run on, so a waiver's deadline reads the same every time. */
export const NOW = new Date('2026-11-07T12:00:00Z');

/** A request that carried a body, as the server would have read it. */
export interface Sent {
  method: string;
  url: string;
  body: string;
  contentType: string | null;
}

export interface Stub {
  /** Every request the app made, as "METHOD /path?query". */
  requests: string[];
  /** The requests that carried a body, in order. */
  sent: Sent[];
}

type Override = (request: { method: string; url: string; body?: string }) => FixtureReply | undefined;

/** Answers fetch from the fixture server. `override` can answer first, to make a route fail or page. */
export function stubFetch({ signedIn = true, override }: { signedIn?: boolean; override?: Override } = {}): Stub {
  const requests: string[] = [];
  const sent: Sent[] = [];
  const state = newFixtureState();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      requests.push(`${method} ${url}`);
      const body = typeof init?.body === 'string' ? init.body : undefined;
      const contentType = new Headers(init?.headers).get('Content-Type');
      if (body !== undefined) sent.push({ method, url, body, contentType });
      const reply =
        override?.({ method, url, body }) ??
        respond({ method, url, cookie: signedIn ? `${SESSION_COOKIE}=1` : '', body, contentType: contentType ?? undefined }, NOW, state);
      const status = reply.status;
      const text = status === 204 || status === 303 ? null : JSON.stringify(reply.body ?? null);
      return new Response(text, { status, headers: { 'Content-Type': 'application/json', ...reply.headers } });
    }),
  );
  return { requests, sent };
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
