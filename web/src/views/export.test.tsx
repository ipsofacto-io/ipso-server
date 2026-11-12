import { act, fireEvent, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FixtureReply } from '../../fixtures/server.ts';
import type { Export } from '../api/types';
import { NOW, renderApp, stubFetch } from '../test/render';

const RECIPIENT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';
const ID = '0194f2a0-0000-7000-8000-000000000a01';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.title = '';
});

const exportJSON = (state: Export['state'], extra: Partial<Export> = {}): Export => ({
  id: ID,
  state,
  requested_by: '0194f2a0-0000-7000-8000-0000000000a1',
  created_at: '2026-11-07T11:00:00Z',
  finished_at: state === 'ready' || state === 'failed' ? '2026-11-07T11:05:00Z' : null,
  expires_at: '2026-11-08T11:05:00Z',
  bytes: state === 'ready' ? 3_500_000 : null,
  sha256: state === 'ready' ? 'ab'.repeat(32) : null,
  ...extra,
});
const reply = (status: number, body: unknown, headers: Record<string, string> = {}): FixtureReply => ({ status, headers, body });
const holding = (current: Export) => ({ method, url }: { method: string; url: string }) =>
  method === 'GET' && url === '/v1/exports/current' ? reply(200, current) : undefined;
const posts = (stub: ReturnType<typeof stubFetch>) => stub.sent.filter((sent) => sent.method === 'POST');
const user = () => userEvent.setup({ advanceTimers: () => {} });
const flush = () =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });

describe('the export screen', () => {
  it('shows the key form when the tenant holds no export', async () => {
    stubFetch();
    renderApp('/export');
    expect(await screen.findByLabelText('Age public key')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Ask for the export' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Download the archive' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Age public key')).toHaveAttribute('autocomplete', 'off');
  });

  it('sends the key and shows the export it was given, with no form while it is made', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/export');
    await u.type(await screen.findByLabelText('Age public key'), `  ${RECIPIENT}  `);
    await u.click(screen.getByRole('button', { name: 'Ask for the export' }));
    expect(await screen.findByRole('heading', { name: 'Waiting for the worker' })).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(1);
    expect(posts(stub)[0]).toMatchObject({ url: '/v1/exports', contentType: 'application/json' });
    expect(JSON.parse(posts(stub)[0]?.body ?? '')).toEqual({ recipient: RECIPIENT });
    expect(screen.queryByLabelText('Age public key')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Download the archive' })).not.toBeInTheDocument();
  });

  it('asks for a key before it sends anything', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/export');
    await u.click(await screen.findByRole('button', { name: 'Ask for the export' }));
    expect(await screen.findByText('Paste the age public key the archive is encrypted to.')).toBeInTheDocument();
    expect(posts(stub)).toHaveLength(0);
  });

  it('never sends a private key, and does not keep it in the field', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp('/export');
    const field = await screen.findByLabelText('Age public key');
    fireEvent.change(field, { target: { value: 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQ' } });
    await u.click(screen.getByRole('button', { name: 'Ask for the export' }));
    expect(await screen.findByText(/That is a private key/)).toBeInTheDocument();
    expect(field).toHaveValue('');
    expect(posts(stub)).toHaveLength(0);
    expect(document.body.textContent).not.toContain('AGE-SECRET-KEY-1QQQ');
  });

  it('says in words that the server could not read the key, and never quotes it', async () => {
    stubFetch({ override: ({ method }) => (method === 'POST' ? reply(400, { error: 'invalid query' }) : undefined) });
    const u = user();
    renderApp('/export');
    await u.type(await screen.findByLabelText('Age public key'), 'age1notakeyatall');
    await u.click(screen.getByRole('button', { name: 'Ask for the export' }));
    expect(await screen.findByText(/could not read the key/)).toBeInTheDocument();
    expect(screen.queryByText(/age1notakeyatall/, { selector: 'p, div.notice-body' })).not.toBeInTheDocument();
  });

  it('says in minutes when to ask again after a 429', async () => {
    stubFetch({
      override: ({ method, url }) => {
        if (method === 'GET' && url === '/v1/exports/current') return reply(200, exportJSON('failed'));
        return method === 'POST' ? reply(429, { error: 'rate limited' }, { 'Retry-After': '541' }) : undefined;
      },
    });
    const u = user();
    renderApp('/export');
    await u.type(await screen.findByLabelText('Age public key'), RECIPIENT);
    await u.click(screen.getByRole('button', { name: 'Ask for the export' }));
    expect(await screen.findByText('Ask again in 10 minutes.')).toBeInTheDocument();
  });

  it('reads the export that is already under way after a 409', async () => {
    let asked = false;
    stubFetch({
      override: ({ method, url }) => {
        if (method === 'POST') {
          asked = true;
          return reply(409, { error: 'conflict' });
        }
        if (url === '/v1/exports/current') return asked ? reply(200, exportJSON('running')) : reply(404, { error: 'not found' });
        return undefined;
      },
    });
    const u = user();
    renderApp('/export');
    await u.type(await screen.findByLabelText('Age public key'), RECIPIENT);
    await u.click(screen.getByRole('button', { name: 'Ask for the export' }));
    expect(await screen.findByRole('heading', { name: 'Being made' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Age public key')).not.toBeInTheDocument();
  });

  it('offers the download only for a ready export, as a link that opens a tab and saves the attachment', async () => {
    stubFetch({ override: holding(exportJSON('ready')) });
    renderApp('/export');
    const link = await screen.findByRole('link', { name: 'Download the archive' });
    expect(link).toHaveAttribute('href', `/v1/exports/${ID}/archive`);
    // No download attribute: a refusal must show as a page, never be saved as a file named .age.
    expect(link).not.toHaveAttribute('download');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByText('3.34 MiB')).toBeInTheDocument();
    expect(screen.getByText('ab'.repeat(32))).toBeInTheDocument();
    expect(screen.getByText(/age --decrypt -i key.txt/)).toBeInTheDocument();
    expect(screen.getByLabelText('Age public key')).toBeInTheDocument();
    expect(screen.getByText(/A new export replaces this one/)).toBeInTheDocument();
  });

  it('offers no download for an export that is pending, running, failed or expired', async () => {
    for (const current of [exportJSON('pending'), exportJSON('running'), exportJSON('failed'), exportJSON('ready', { expires_at: '2026-11-07T11:59:59Z' })]) {
      stubFetch({ override: holding(current) });
      const view = renderApp('/export');
      await screen.findByRole('heading', { level: 2 });
      expect(screen.queryByRole('link', { name: 'Download the archive' })).not.toBeInTheDocument();
      view.unmount();
      vi.unstubAllGlobals();
    }
  });

  it('shows a failed export and the form to ask again', async () => {
    stubFetch({ override: holding(exportJSON('failed')) });
    renderApp('/export');
    expect(await screen.findByRole('heading', { name: 'Failed' })).toBeInTheDocument();
    expect(screen.getByText(/The log of the worker says why/)).toBeInTheDocument();
    expect(screen.getByLabelText('Age public key')).toBeInTheDocument();
  });

  it('shows the refusal and nothing else to a person without the role', async () => {
    stubFetch({ override: ({ url }) => (url === '/v1/exports/current' ? reply(403, { error: 'forbidden' }) : undefined) });
    renderApp('/export');
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Age public key')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Ask for the export' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Export' })).not.toBeInTheDocument();
  });
});

describe('the export entry and the page share one read', () => {
  it('reads the export once on the page, which tells the menu', async () => {
    const stub = stubFetch();
    renderApp('/export');
    expect(await screen.findByLabelText('Age public key')).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Export' })).toBeInTheDocument();
    expect(stub.requests.filter((request) => request === 'GET /v1/exports/current')).toHaveLength(1);
  });

  it('keeps the menu entry when the read fails for a reason that is not a refusal', async () => {
    stubFetch({ override: ({ url }) => (url === '/v1/exports/current' ? reply(503, { error: 'timeout' }) : undefined) });
    renderApp('/export');
    expect(await screen.findByText('The request took too long.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Export' })).toBeInTheDocument();
  });
});

describe('the export while it is made', () => {
  it('reads it again every few seconds and offers the download once it is ready', async () => {
    vi.useRealTimers();
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] });
    vi.setSystemTime(NOW);
    let reads = 0;
    const states: Export['state'][] = ['pending', 'running', 'ready'];
    stubFetch({
      override: ({ method, url }) => {
        if (method !== 'GET' || url !== '/v1/exports/current') return undefined;
        const state = states[Math.min(reads, states.length - 1)] ?? 'ready';
        reads += 1;
        return reply(200, exportJSON(state));
      },
    });
    renderApp('/export');
    await flush();
    expect(screen.getByRole('heading', { name: 'Waiting for the worker' })).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(screen.getByRole('heading', { name: 'Being made' })).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(screen.getByRole('link', { name: 'Download the archive' })).toBeInTheDocument();
    // A ready export is not read again.
    const before = reads;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(20000);
    });
    expect(reads).toBe(before);
  });
});

describe('a ready export that expires while the page is open', () => {
  it('drops the download and shows the form once the server says it is gone', async () => {
    vi.useRealTimers();
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(NOW);
    let reads = 0;
    stubFetch({
      override: ({ method, url }) => {
        if (method !== 'GET' || url !== '/v1/exports/current') return undefined;
        reads += 1;
        return reads === 1 ? reply(200, exportJSON('ready', { expires_at: new Date(NOW.getTime() + 3000).toISOString() })) : reply(404, { error: 'not found' });
      },
    });
    renderApp('/export');
    await flush();
    expect(screen.getByRole('link', { name: 'Download the archive' })).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4100);
    });
    expect(screen.queryByRole('link', { name: 'Download the archive' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Age public key')).toBeInTheDocument();
  });
});
