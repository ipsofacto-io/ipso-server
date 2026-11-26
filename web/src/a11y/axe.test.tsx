import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ids } from '../../fixtures/data.ts';
import { FIXTURE_TENANTS } from '../../fixtures/server.ts';
import { NOW, renderApp, stubFetch } from '../test/render';

// jsdom applies no stylesheet, so color-contrast cannot see a paint. contrast.test.ts holds those pairs.
// target-size is off in axe until a caller enables it, and a zero-size box would fail it here.
const RULES: axe.RunOptions = {
  runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
  rules: { 'color-contrast': { enabled: false } },
};

const COMMIT = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  document.documentElement.lang = 'en';
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.title = '';
  window.location.hash = '';
});

function reported(results: axe.AxeResults): string[] {
  return results.violations.flatMap((violation) =>
    violation.nodes.slice(0, 3).map((node) => `${violation.id}: ${node.target.join(' ')} ${node.html.slice(0, 140)}`),
  );
}

async function expectClean(): Promise<void> {
  expect(reported(await axe.run(document, RULES))).toEqual([]);
}

describe('the page shell', () => {
  it('names the language and does not lock the zoom', () => {
    const page = readFileSync(join(process.cwd(), 'index.html'), 'utf8');
    expect(page).toContain('<html lang="en">');
    expect(page).toContain('width=device-width, initial-scale=1');
    expect(page).not.toContain('maximum-scale');
    expect(page).not.toContain('user-scalable=no');
  });
});

describe('WCAG 2.2 A and AA on each route', () => {
  const pages: { path: string; settle: () => Promise<unknown>; signedIn?: boolean }[] = [
    { path: '/decisions', settle: () => screen.findByRole('table', { name: 'Decisions in force' }) },
    { path: '/decisions/new', settle: () => screen.findByRole('button', { name: 'Check verifiability' }) },
    { path: `/decisions/${ids.useTls}`, settle: () => screen.findByRole('heading', { level: 2, name: 'Public ingress terminates TLS 1.2 or later' }) },
    { path: '/decisions/no-such-decision', settle: () => screen.findByText('No decision matches this reference.') },
    { path: '/scopes', settle: () => screen.findByText('acme', { exact: true }) },
    {
      path: '/inbox',
      settle: async () => {
        await screen.findByText('Services read secrets from the vault, not from environment files');
        await screen.findByText('Public endpoints need rate limits');
        await screen.findByText('Check for decision 0194f2a0, version 2');
      },
    },
    { path: '/waivers', settle: () => screen.findByRole('table', { name: 'Waivers in force' }) },
    { path: '/waivers/new', settle: () => screen.findByRole('button', { name: 'Record the waiver' }) },
    {
      path: '/premises',
      settle: async () => {
        await screen.findByRole('link', { name: 'https://status.example.com/bastion.json' });
        await screen.findByRole('button', { name: 'Withdraw status.example.com' });
      },
    },
    { path: '/supersessions/new', settle: () => screen.findByRole('button', { name: 'Record the supersession' }) },
    { path: '/baselines/new', settle: () => screen.findByRole('button', { name: 'Record the baseline' }) },
    { path: '/export', settle: () => screen.findByRole('button', { name: 'Ask for the export' }) },
    { path: '/invitations', settle: () => screen.findByRole('button', { name: 'Invite the person' }) },
    { path: '/audit', settle: () => screen.findByRole('link', { name: 'What applied' }) },
    { path: '/audit/decisions', settle: () => screen.findByRole('button', { name: 'Ask' }) },
    { path: '/audit/decisions?repo=acme/payments&valid=2026-11-07T12:00:00Z&known=2026-11-07T12:00:00Z', settle: () => screen.findByRole('table', { name: 'Decisions that applied' }) },
    { path: '/audit/beliefs?repo=acme/payments&valid=2026-11-07T00:00:00Z&then=2026-10-01T00:00:00Z&now=2026-11-07T00:00:00Z', settle: () => screen.findByRole('table', { name: 'Decisions that changed' }) },
    { path: `/audit/merges?repo=acme/payments&sha=${COMMIT}&at=2026-11-01T00:00:00Z`, settle: () => screen.findByRole('table', { name: 'Verdicts of the runs on the commit' }) },
    { path: `/audit/supersessions?decision=${ids.legacyFtp}&known=2026-11-07T12:00:00Z`, settle: () => screen.findByRole('table', { name: 'Supersession links' }) },
    { path: '/audit/waivers?known=2026-11-07T12:00:00Z&now=2026-11-07T12:00:00Z', settle: () => screen.findByRole('table', { name: 'Waivers ending soon' }) },
    { path: '/pages', settle: () => screen.findByRole('heading', { name: 'All pages' }) },
    { path: '/missing', settle: () => screen.findByRole('heading', { name: 'Not found' }) },
    { path: '/signin', settle: () => screen.findByRole('heading', { level: 2, name: 'Sign in to ipso' }), signedIn: false },
  ];

  it.each(pages)('$path has no A or AA violation', async ({ path, settle, signedIn }) => {
    stubFetch({ signedIn });
    renderApp(path);
    await settle();
    await expectClean();
  });

  it('has no violation when a required audit field is refused', async () => {
    stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/audit/decisions');
    await user.click(await screen.findByRole('button', { name: 'Ask' }));
    expect(await screen.findByText('Required.')).toBeInTheDocument();
    await expectClean();
  });

  it('has no violation when a read is refused', async () => {
    stubFetch({ override: ({ url }) => (url.startsWith('/v1/decisions') ? { status: 403, headers: {}, body: { error: 'forbidden' } } : undefined) });
    renderApp('/decisions');
    expect(await screen.findByRole('alert')).toHaveTextContent('You do not have a role that allows this.');
    await expectClean();
  });

  it('has no violation on a sign-in that did not finish', async () => {
    window.location.hash = '#code=unknown_login&issuer=https%3A%2F%2Fgithub.com&subject=123';
    stubFetch({ signedIn: false });
    renderApp('/signin');
    expect(await screen.findByRole('alert')).toHaveTextContent('This account is not a member of this organization.');
    await expectClean();
  });

  it('has no violation on an invitation link', async () => {
    window.location.hash = `#${'a'.repeat(43)}`;
    stubFetch({ signedIn: false });
    renderApp('/invitation');
    await screen.findByRole('heading', { level: 2, name: 'You are invited to ipso' });
    await screen.findByRole('button', { name: 'Sign in with GitHub' });
    await expectClean();
  });

  it('has no A or AA violation in the dark theme', async () => {
    document.documentElement.dataset.theme = 'dark';
    stubFetch();
    renderApp('/decisions');
    await screen.findByRole('table', { name: 'Decisions in force' });
    await expectClean();
    delete document.documentElement.dataset.theme;
  });

  it('has no violation when the invitation link is incomplete', async () => {
    stubFetch({ signedIn: false });
    renderApp('/invitation');
    expect(await screen.findByRole('alert')).toHaveTextContent('This invitation link is not complete.');
    await expectClean();
  });

  it('has no violation on the tenant choice page', async () => {
    stubFetch({
      signedIn: false,
      override: ({ method, url }) =>
        method === 'GET' && url === '/auth/tenants' ? { status: 200, headers: {}, body: { tenants: FIXTURE_TENANTS, flow: 'browser' } } : undefined,
    });
    renderApp('/signin/tenant');
    await screen.findByRole('heading', { level: 2, name: 'Choose an organization' });
    await screen.findByRole('button', { name: 'Acme Europe' });
    await expectClean();
  });
});
