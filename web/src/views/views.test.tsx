import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useNavigate } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decisions, ids } from '../../fixtures/data.ts';
import { AppRoutes } from '../App';
import { AppProvider } from '../app/AppContext';
import { NOW, renderApp, stubFetch } from '../test/render';


/** The layout also reads the export once a person is signed in, to decide whether the menu has the Export entry (ADR-0115). */
const MENU_READ = 'GET /v1/exports/current';
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.title = '';
});

describe('the registry', () => {
  it('shows every state of the lifecycle with a word, and Verified only for a verified decision', async () => {
    stubFetch();
    renderApp('/decisions');
    const table = await screen.findByRole('table', { name: 'Decisions in force' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(decisions.length);

    const stateOf = (title: string) => within(within(table).getByRole('link', { name: title }).closest('tr') as HTMLElement);
    expect(stateOf('Public ingress terminates TLS 1.2 or later').getByText('Verified')).toBeInTheDocument();
    expect(stateOf('Base images are pinned by digest').getByText('Verifying')).toBeInTheDocument();
    expect(stateOf('Admin ports are open only from the bastion').getByText('Needs review')).toBeInTheDocument();
    expect(stateOf('PostgreSQL is the only primary store').getByText('Rejected')).toBeInTheDocument();
    expect(stateOf('Replace the legacy FTP gateway').getByText('Superseded')).toBeInTheDocument();
    expect(stateOf('Retire the old message queue').getByText('Deprecated')).toBeInTheDocument();
    const proposed = stateOf('No dynamic code execution in services');
    expect(proposed.getByText('Verifying')).toBeInTheDocument();
    expect(proposed.getByText('Pending approval')).toBeInTheDocument();

    // Menta is the Verified status and nothing else, and the one Verified icon belongs to the two verified decisions.
    expect(table.querySelectorAll('.ip-status-verified')).toHaveLength(2);
    expect(document.title).toBe('Decisions · ipso');
  });

  it('links a decision by its registry id and never sends a tenant', async () => {
    const stub = stubFetch();
    renderApp('/decisions');
    const link = await screen.findByRole('link', { name: 'File transfer uses SFTP only' });
    expect(link).toHaveAttribute('href', `/decisions/${ids.sftpOnly}`);
    expect(stub.requests.join('\n')).not.toMatch(/tenant/);
    expect(stub.requests[0]).toBe('GET /v1/decisions?limit=50');
  });

  it('filters the decisions that are loaded', async () => {
    stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions');
    await screen.findByRole('table', { name: 'Decisions in force' });
    await user.type(screen.getByLabelText('Filter'), 'sftp');
    const table = screen.getByRole('table', { name: 'Decisions in force' });
    expect(within(table).getAllByRole('row')).toHaveLength(2);
    await user.clear(screen.getByLabelText('Filter'));
    await user.type(screen.getByLabelText('Filter'), 'nothing matches this');
    expect(screen.getByText('No loaded decision matches this filter.')).toBeInTheDocument();
  });

  it('asks again at a time read from the address', async () => {
    const stub = stubFetch();
    renderApp('/decisions?valid=2026-03-01T00:00:00Z&known=2026-03-02T00:00:00Z');
    await screen.findByRole('table', { name: 'Decisions in force' });
    expect(stub.requests[0]).toBe('GET /v1/decisions?valid=2026-03-01T00%3A00%3A00Z&known=2026-03-02T00%3A00%3A00Z&limit=50');
    expect(screen.getByText('2026-03-01 00:00 UTC, as known 2026-03-02 00:00 UTC')).toBeInTheDocument();
  });

  it('pages from the last id and stops when a page is short', async () => {
    const make = (from: number, count: number) =>
      Array.from({ length: count }, (_, i) => ({ id: `0194f2a0-0000-7000-8000-${String(900 - from - i).padStart(12, '0')}`, version: 1, body: { slug: `d-${from + i}`, title: `Decision ${from + i}`, status: 'verified' } }));
    const stub = stubFetch({
      override: ({ url }) => {
        if (!url.startsWith('/v1/decisions?')) return undefined;
        const before = new URL(url, 'http://x').searchParams.get('before');
        return { status: 200, headers: {}, body: { valid: '2026-11-07T12:00:00Z', known: '2026-11-07T12:00:00Z', decisions: before ? make(50, 3) : make(0, 50) } };
      },
    });
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions');
    await screen.findByRole('link', { name: 'Decision 0' });
    expect(screen.getByRole('button', { name: 'Load more' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load more' }));
    await screen.findByRole('link', { name: 'Decision 52' });
    expect(stub.requests.at(-1)).toBe(`GET /v1/decisions?limit=50&before=0194f2a0-0000-7000-8000-${String(900 - 49).padStart(12, '0')}`);
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /^Decision \d+$/ })).toHaveLength(53);
  });

  it('says what an empty registry holds, in the brand voice', async () => {
    stubFetch({ override: ({ url }) => (url.startsWith('/v1/decisions') ? { status: 200, headers: {}, body: { valid: 'x', known: 'x', decisions: [] } } : undefined) });
    renderApp('/decisions');
    expect(await screen.findByText('No decisions yet.')).toBeInTheDocument();
    expect(screen.getByText('Your first receipt will appear here.')).toBeInTheDocument();
  });
});

describe('a decision', () => {
  it('shows its record, its checks and its CI verdicts, and links only to https', async () => {
    const stub = stubFetch();
    renderApp(`/decisions/${ids.useTls}`);
    expect(await screen.findByRole('heading', { name: 'Public ingress terminates TLS 1.2 or later' })).toBeInTheDocument();
    expect(screen.getByText('team:security')).toBeInTheDocument();
    expect(screen.getByText('2027-02-01')).toBeInTheDocument();
    const checks = screen.getByRole('table', { name: 'Checks of this decision' });
    expect(within(checks).getByText('CKV_AWS_103')).toBeInTheDocument();
    expect(within(checks).getByText('require-tls-ingress')).toBeInTheDocument();

    expect(screen.getByRole('link', { name: 'https://github.com/acme/platform/pull/70' })).toHaveAttribute('href', 'https://github.com/acme/platform/pull/70');
    expect(screen.queryByRole('link', { name: /javascript/ })).not.toBeInTheDocument();
    expect(screen.getByText('javascript:alert(1)')).toBeInTheDocument();

    const verdicts = await screen.findByRole('table', { name: 'Verdicts uploaded by CI runs' });
    const rows = within(verdicts).getAllByRole('row').slice(1);
    const rowAt = (index: number) => {
      const row = rows[index];
      if (!row) throw new Error(`no verdict row ${index}`);
      return row;
    };
    expect(rows).toHaveLength(6);
    expect(within(rowAt(0)).getByText('pass')).toBeInTheDocument();
    expect(within(rowAt(1)).getByText('fail')).toHaveClass('result-bad');
    expect(within(rowAt(2)).getByText('waived')).not.toHaveClass('result-bad');
    // A verdict with no digest has no reading, so it has no line about the baseline.
    expect(within(rowAt(0)).queryByText(/recorded baseline/)).not.toBeInTheDocument();
    expect(within(rowAt(0)).queryByText(/recorded waiver/)).not.toBeInTheDocument();
    expect(within(verdicts).getByRole('link', { name: '9912345.1' })).toHaveAttribute('href', 'https://github.com/acme/payments/actions/runs/9912345');
    expect(stub.requests.some((request) => request.startsWith('GET /v1/verdicts?decision=01JB015QEHVBS2Q67NPD1BPZ2E'))).toBe(true);
  });

  it('shows a verdict as the recorded baseline reads it and says what the run reported when that differs', async () => {
    renderAndStub(`/decisions/${ids.useTls}`);
    const verdicts = await screen.findByRole('table', { name: 'Verdicts uploaded by CI runs' });
    const rows = within(verdicts).getAllByRole('row').slice(1);
    const rowAt = (index: number) => {
      const row = rows[index];
      if (!row) throw new Error(`no verdict row ${index}`);
      return row;
    };

    // The run failed and every digest it sent is in the baseline: the registry reads it as waived.
    expect(within(rowAt(3)).getByText('waived(baseline)')).not.toHaveClass('result-bad');
    expect(within(rowAt(3)).getByText('3 of 3 in the recorded baseline, the run reported fail')).toBeInTheDocument();
    expect(within(rowAt(3)).queryByText('fail')).not.toBeInTheDocument();

    // The run waived its violations with a local file that nobody recorded: the registry reads fail.
    expect(within(rowAt(4)).getByText('fail')).toHaveClass('result-bad');
    expect(within(rowAt(4)).getByText('0 of 2 in the recorded baseline, the run reported waived')).toBeInTheDocument();
    expect(within(rowAt(4)).queryByText('waived')).not.toBeInTheDocument();
  });

  it('shows a verdict as the recorded waivers read it, with the day the waiver ends, and says what the run reported when that differs', async () => {
    renderAndStub(`/decisions/${ids.useTls}`);
    const verdicts = await screen.findByRole('table', { name: 'Verdicts uploaded by CI runs' });
    const rows = within(verdicts).getAllByRole('row').slice(1);
    const rowAt = (index: number) => {
      const row = rows[index];
      if (!row) throw new Error(`no verdict row ${index}`);
      return row;
    };

    // The run failed and a recorded waiver covers it: the registry reads it as waived.
    expect(within(rowAt(5)).getByText('waived')).not.toHaveClass('result-bad');
    expect(within(rowAt(5)).getByText(/^covered by a recorded waiver until \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC, the run reported fail$/)).toBeInTheDocument();
    expect(within(rowAt(5)).queryByText('fail')).not.toBeInTheDocument();

    // The run waived it and a recorded waiver agrees: nothing differs to report.
    expect(within(rowAt(2)).getByText(/^covered by a recorded waiver until \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/)).toBeInTheDocument();

    // A fail that no recorded waiver covers shows no line about waivers.
    expect(within(rowAt(1)).getByText('fail')).toHaveClass('result-bad');
    expect(within(rowAt(1)).queryByText(/recorded waiver/)).not.toBeInTheDocument();
  });

  it('names the successor of a superseded decision', async () => {
    renderAndStub(`/decisions/${ids.legacyFtp}`);
    const link = await screen.findByRole('link', { name: 'this decision' });
    expect(link).toHaveAttribute('href', `/decisions/${ids.sftpOnly}`);
    expect(screen.getByText(/from 2026-06-01 00:00 UTC/)).toBeInTheDocument();
  });

  it('asks nothing about a successor for a decision that is in force', async () => {
    const stub = stubFetch();
    renderApp(`/decisions/${ids.useTls}`);
    await screen.findByRole('heading', { name: 'Public ingress terminates TLS 1.2 or later' });
    expect(stub.requests.some((request) => request.includes('/v1/audit/supersessions'))).toBe(false);
  });

  it('says so when a reference names no decision', async () => {
    stubFetch();
    renderApp('/decisions/no-such-decision');
    expect(await screen.findByText('No decision matches this reference.')).toBeInTheDocument();
  });
});

function renderAndStub(path: string) {
  const stub = stubFetch();
  renderApp(path);
  return stub;
}

describe('scopes', () => {
  it('draws the tree from the flat list', async () => {
    renderAndStub('/scopes');
    const org = (await screen.findByText('acme')).closest('li') as HTMLElement;
    const service = within(org).getByText('payments').closest('li') as HTMLElement;
    const repo = within(service).getByText('acme/payments').closest('li') as HTMLElement;
    expect(within(repo).getByText('deploy/**')).toBeInTheDocument();
    expect(within(repo).getByText('prod')).toBeInTheDocument();
  });
});

describe('the inbox', () => {
  it('lists the three queues and reads them with GET only until a person answers a draft', async () => {
    const stub = renderAndStub('/inbox');
    expect(await screen.findByRole('heading', { name: 'Pull requests' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Coding agents' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Drafted checks' })).toBeInTheDocument();
    expect(await screen.findByText('Services read secrets from the vault, not from environment files')).toBeInTheDocument();
    expect(await screen.findByText('Public endpoints need rate limits')).toBeInTheDocument();
    expect(await screen.findByText('Check for decision 0194f2a0, version 2')).toBeInTheDocument();
    expect(screen.getAllByText('Pending approval')).toHaveLength(4);
    expect(screen.getByText(/Approving a drafted check records the answer only/)).toBeInTheDocument();
    expect(stub.requests.every((request) => request.startsWith('GET '))).toBe(true);
  });

  it('treats a draft as text: no script runs, no link to a scheme that is not https, no author', async () => {
    renderAndStub('/inbox');
    await screen.findByText('Services read secrets from the vault, not from environment files');
    await screen.findByText('retry-with-backoff');
    expect(document.querySelector('script')).toBeNull();
    expect(screen.getByRole('link', { name: 'acme/payments#412' })).toHaveAttribute('href', 'https://github.com/acme/payments/pull/412');
    expect(screen.queryByRole('link', { name: 'acme/ledger#98' })).not.toBeInTheDocument();
    expect(screen.getByText('acme/ledger#98')).toBeInTheDocument();
    // ADR-0012: nobody is a dimension of the views, and an agent proposal does not name its principal.
    expect(screen.queryByText(/0194f2a0-0000-7000-8000-000000000900/)).not.toBeInTheDocument();
    expect(screen.getByText('A coding agent')).toBeInTheDocument();
  });
});

describe('waivers', () => {
  it('says in words when each one ends, and which scope it covers', async () => {
    renderAndStub('/waivers');
    const table = await screen.findByRole('table', { name: 'Waivers in force' });
    const row = (ticket: string) => within(within(table).getByText(ticket).closest('tr') as HTMLElement);
    expect(row('SEC-482').getByText('Expires in 40 days')).not.toHaveClass('deadline-soon');
    expect(row('OPS-1190').getByText('Expires in 3 days')).toHaveClass('deadline-soon');
    expect(row('PLAT-77').getByText('Expires within a day')).toHaveClass('deadline-soon');
    await waitFor(() => expect(row('OPS-1190').getByText('repo acme/payments')).toBeInTheDocument());
    expect(row('PLAT-77').getByText('path deploy/**')).toBeInTheDocument();
  });
});

describe('the audit', () => {
  it('lists the five questions', async () => {
    renderAndStub('/audit');
    for (const name of ['What applied', 'What changed', 'At a merge', 'Supersessions', 'Waivers ending soon']) {
      expect(await screen.findByRole('link', { name })).toBeInTheDocument();
    }
  });

  it('asks nothing until the required fields are there, and says which is missing', async () => {
    const stub = stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/audit/decisions');
    await user.click(screen.getByRole('button', { name: 'Ask' }));
    expect(screen.getByText('Required.')).toBeInTheDocument();
    expect(stub.requests).toHaveLength(0);
  });

  it('asks Q1 with the subject and both times, in UTC', async () => {
    const stub = stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/audit/decisions');
    await user.type(screen.getByLabelText('Repository'), 'acme/payments');
    await user.click(screen.getByRole('button', { name: 'Ask' }));
    expect(await screen.findByRole('table', { name: 'Decisions that applied' })).toBeInTheDocument();
    expect(stub.requests).toEqual(['GET /v1/audit/decisions?repo=acme%2Fpayments&valid=2026-11-07T12%3A00%3A00Z&known=2026-11-07T12%3A00%3A00Z', MENU_READ]);
  });

  it('answers Q2 with what was added, removed and changed', async () => {
    renderAndStub('/audit/beliefs?repo=acme/payments&valid=2026-11-07T00:00:00Z&then=2026-10-01T00:00:00Z&now=2026-11-07T00:00:00Z');
    const changed = await screen.findByRole('table', { name: 'Decisions that changed' });
    expect(within(changed).getByText('Verifying')).toBeInTheDocument();
    expect(within(changed).getByText('Verified')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Decisions added' })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Decisions removed' })).toBeInTheDocument();
  });

  it('answers Q3 for the time a change merged', async () => {
    const stub = renderAndStub('/audit/merges?repo=acme/payments&at=2026-11-01T00:00:00Z');
    expect(await screen.findByRole('table', { name: 'Decisions at the merge' })).toBeInTheDocument();
    expect(stub.requests).toEqual(['GET /v1/audit/merges?repo=acme%2Fpayments&at=2026-11-01T00%3A00%3A00Z', MENU_READ]);
  });

  it('answers Q4 from the link on a decision, with the chain and its versions', async () => {
    renderAndStub(`/audit/supersessions?decision=${ids.legacyFtp}&known=2026-11-07T12:00:00Z`);
    expect(await screen.findByRole('table', { name: 'Supersession links' })).toBeInTheDocument();
    const versions = screen.getByRole('table', { name: 'Versions of the decisions in the chain' });
    expect(within(versions).getByText('open')).toBeInTheDocument();
    expect(within(versions).getAllByRole('row')).toHaveLength(3);
  });

  it('answers Q5 and ignores a key in the address that the question does not take', async () => {
    const stub = renderAndStub('/audit/waivers?known=2026-11-07T12:00:00Z&now=2026-11-07T12:00:00Z&tenant=other');
    expect(await screen.findByRole('table', { name: 'Waivers ending soon' })).toBeInTheDocument();
    expect(stub.requests).toEqual(['GET /v1/audit/waivers?known=2026-11-07T12%3A00%3A00Z&now=2026-11-07T12%3A00%3A00Z', MENU_READ]);
  });

  it('says a question is too wide when the answer is over the cap', async () => {
    stubFetch({ override: ({ url }) => (url.startsWith('/v1/audit/merges') ? { status: 500, headers: {}, body: { error: 'response too large' } } : undefined) });
    renderApp('/audit/merges?repo=acme/payments&at=2026-11-01T00:00:00Z');
    expect(await screen.findByText('The answer is too large to show.')).toBeInTheDocument();
    expect(screen.getByText('Narrow the question with a path or an environment.')).toBeInTheDocument();
  });
});

describe('the time controls and the address', () => {
  it('applies a time to the address and clears it with Now', async () => {
    const stub = stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/waivers');
    await screen.findByRole('table', { name: 'Waivers in force' });
    await user.click(screen.getByText('As of'));
    fireEvent.change(screen.getByLabelText('In force at (UTC)'), { target: { value: '2026-03-01T10:30' } });
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    await waitFor(() => expect(stub.requests.at(-1)).toBe('GET /v1/waivers?valid=2026-03-01T10%3A30%3A00Z&limit=50'));
    expect(screen.getByText('2026-03-01 10:30 UTC, as known now')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Now' }));
    await waitFor(() => expect(stub.requests.at(-1)).toBe('GET /v1/waivers?limit=50'));
    expect(screen.getByLabelText('In force at (UTC)')).toHaveValue('');
  });

  it('follows the address when it changes under the form, as back and forward do', async () => {
    stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    function Jump({ to }: { to: string }) {
      const navigate = useNavigate();
      return <button onClick={() => navigate(to)}>jump</button>;
    }
    render(
      <AppProvider>
        <MemoryRouter initialEntries={['/audit/decisions?repo=acme/api&valid=2026-03-01T10:00:00Z&known=2026-03-02T10:00:00Z']}>
          <Jump to="/audit/decisions?repo=globex/web&valid=2026-05-05T08:15:00Z&known=2026-05-06T08:15:00Z" />
          <AppRoutes />
        </MemoryRouter>
      </AppProvider>,
    );
    expect(screen.getByLabelText('Repository')).toHaveValue('acme/api');
    expect(screen.getByLabelText('In force at (UTC)')).toHaveValue('2026-03-01T10:00');
    await user.click(screen.getByRole('button', { name: 'jump' }));
    await waitFor(() => expect(screen.getByLabelText('Repository')).toHaveValue('globex/web'));
    expect(screen.getByLabelText('In force at (UTC)')).toHaveValue('2026-05-05T08:15');
    expect(screen.getByLabelText('Known at (UTC)')).toHaveValue('2026-05-06T08:15');
  });

  it('loads the scopes once for the tree and once more for the waivers, not twice', async () => {
    const stub = stubFetch();
    renderApp('/scopes');
    await screen.findByText('acme');
    expect(stub.requests.filter((request) => request.startsWith('GET /v1/scopes'))).toHaveLength(1);
  });
});
