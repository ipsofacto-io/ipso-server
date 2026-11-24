import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ids } from '../../fixtures/data.ts';
import { NOW, renderApp, stubFetch } from '../test/render';

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  document.title = '';
});

describe('decision health and assisted authoring', () => {
  it('shows separate Validity and Compliance axes, live vs CI verdicts, and AI-generated label on engine llm verdicts', async () => {
    stubFetch();
    renderApp(`/decisions/${ids.useTls}`);
    expect(await screen.findByRole('heading', { name: 'Public ingress terminates TLS 1.2 or later' })).toBeInTheDocument();
    const healthSection = await screen.findByRole('region', { name: 'Validity and compliance' });
    expect(within(healthSection).getByText('needs_review')).toBeInTheDocument();
    const table = within(healthSection).getByRole('table', { name: 'Compliance health by scope' });
    expect(within(table).getByText('acme/payments / prod')).toBeInTheDocument();
    expect(within(table).getByText('AI-generated')).toBeInTheDocument();
    expect(within(table).getByText('mistral-large-latest, prompt llmcheck-v1')).toBeInTheDocument();
  });

  it('searches the registry with full-text q parameter', async () => {
    const stub = stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions');
    await screen.findByRole('table', { name: 'Decisions in force' });
    await user.type(screen.getByLabelText('Search registry'), 'tls');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    expect(await screen.findByRole('link', { name: 'Public ingress terminates TLS 1.2 or later' })).toBeInTheDocument();
    expect(stub.requests.some((r) => r.startsWith('GET /v1/decisions?q=tls&limit=50'))).toBe(true);
  });

  it('analyzes verifiability, enforces engine llm block fixtures, and records a contextual approval', async () => {
    const stub = stubFetch();
    const user = userEvent.setup({ advanceTimers: () => {} });
    renderApp('/decisions/new');

    await user.type(screen.getByLabelText('Title'), 'Deny unrestricted production egress');
    await user.type(screen.getByLabelText('Decision statement'), 'Use firewall rules where appropriate.');
    await user.click(screen.getByRole('button', { name: 'Check verifiability' }));

    const analysis = await screen.findByRole('region', { name: 'Verifiability analysis' });
    expect(within(analysis).getByText('Verifiability: ambiguous')).toBeInTheDocument();
    expect(within(analysis).getByText('AI-generated')).toBeInTheDocument();
    expect(within(analysis).getByText('mistral-large-latest, prompt verifiability-v1')).toBeInTheDocument();

    await user.click(within(analysis).getByRole('button', { name: 'Use llm check' }));
    expect(screen.getByLabelText('Check 1 rubric')).toBeInTheDocument();

    // Switch check 1 mode to block and clear deny fixture input to verify client gate.
    await user.selectOptions(screen.getByLabelText('Check 1 mode'), 'block');
    await user.clear(screen.getByLabelText('Check 1 fixture 2 input'));
    const acmeCheckbox = await screen.findByRole('checkbox', { name: /org acme/i });
    await user.click(acmeCheckbox);
    await user.click(screen.getByRole('button', { name: 'Submit proposal' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('mode block on engine llm requires at least one allow fixture and one deny fixture');

    // Restore deny fixture input and approve immediately.
    await user.type(screen.getByLabelText('Check 1 fixture 2 input'), '0.0.0.0/0');
    await user.click(screen.getByRole('checkbox', { name: /Approve and record immediately/i }));
    await user.click(screen.getByRole('button', { name: 'Approve and record decision' }));

    expect(await screen.findByText('Decision approved and recorded.')).toBeInTheDocument();
    expect(stub.requests).toContain('POST /v1/verifiability');
    expect(stub.requests).toContain('POST /v1/human-proposals');
  });
});
