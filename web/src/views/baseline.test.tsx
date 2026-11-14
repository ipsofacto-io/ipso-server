import { fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decisions, ids } from '../../fixtures/data.ts';
import type { FixtureReply } from '../../fixtures/server.ts';
import { digestsThatFit } from '../state/baseline';
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

const EDR = String(decisions.find((decision) => decision.id === ids.useTls)?.body.id);
const PATH = `/v1/decisions/${ids.useTls}/baselines`;
const PAGE = `/baselines/new?decision=${ids.useTls}`;
const digest = (n: number) => n.toString(16).padStart(64, '0');
const digests = (n: number) => Array.from({ length: n }, (_, i) => digest(i));
const exported = (fingerprints: string[] = digests(3), decisionId: string = EDR) =>
  JSON.stringify({ baseline_export_version: 1, decision_id: decisionId, fingerprints }, null, 2);
const file = (text: string, name = 'baseline-export.json') => new File([text], name, { type: 'application/json' });
const reply = (status: number, error: string): FixtureReply => ({ status, headers: {}, body: { error } });
const user = () => userEvent.setup({ advanceTimers: () => {} });
const baselines = (stub: ReturnType<typeof stubFetch>) => stub.sent.filter((sent) => sent.url === PATH);
const change = (label: string | RegExp, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });

/** The decision has its grandfather terms, as the supersession page records them, in the same fixtures run. */
async function recordTerms() {
  const response = await fetch(`/v1/decisions/${ids.useTls}/grandfather-period`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ valid_from: '2026-11-07T12:00:00Z' }),
  });
  expect(response.status).toBe(201);
}

async function fill(u: ReturnType<typeof user>, text = exported(), repo = 'acme/payments') {
  await screen.findByRole('heading', { name: 'Record a baseline' });
  await screen.findByRole('option', { name: /Public ingress terminates TLS/ });
  await waitFor(() => expect(screen.getByLabelText('Decision')).toHaveValue(ids.useTls));
  change('Repository', repo);
  await u.upload(screen.getByLabelText('Baseline file'), file(text));
}

describe('recording a baseline', () => {
  it('sends the repository and the digests of the export, and says what was recorded', async () => {
    const stub = stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    await fill(u);
    expect(await screen.findByText('baseline-export.json holds 3 fingerprints.')).toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));

    expect(await screen.findByText('Baseline recorded.')).toBeInTheDocument();
    expect(screen.getByText(/3 fingerprints are recorded for acme\/payments under Public ingress terminates TLS/)).toBeInTheDocument();
    const [sent, ...others] = baselines(stub);
    expect(others).toHaveLength(0);
    expect(sent).toMatchObject({ method: 'POST', contentType: 'application/json' });
    const body = JSON.parse(sent?.body ?? '{}');
    expect(Object.keys(body)).toEqual(['repo', 'fingerprints']);
    expect(body).toEqual({ repo: 'acme/payments', fingerprints: digests(3) });
    // The tenant and the principal come from the session, and the file's own keys are not sent.
    expect(sent?.body).not.toMatch(/tenant|principal|approver|salt|decision/i);
    expect(screen.getByRole('link', { name: 'Open the decision' })).toHaveAttribute('href', `/decisions/${ids.useTls}`);
  });

  it('says how to make the file, with the EDR id of the chosen decision', async () => {
    stubFetch();
    renderApp(PAGE);
    await screen.findByRole('option', { name: /Public ingress terminates TLS/ });
    await waitFor(() => expect(screen.getByText(`ipso baseline export ${EDR} > baseline-export.json`)).toBeInTheDocument());
    expect(screen.getByText(/It holds fingerprints and no salt/)).toBeInTheDocument();
  });

  it('can record a second repository for the same decision', async () => {
    const stub = stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    await fill(u);
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    await screen.findByText('Baseline recorded.');
    await u.click(screen.getByRole('button', { name: 'Record another repository' }));
    await fill(u, exported(digests(2)), 'acme/web');
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText(/2 fingerprints are recorded for acme\/web/)).toBeInTheDocument();
    expect(baselines(stub)).toHaveLength(2);
  });
});

describe('the checks before the request', () => {
  it('refuses a file made for another decision, and sends nothing', async () => {
    const stub = stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    await fill(u, exported(digests(3), '01M5C5QEHHNXJ3D7X2ZCMGXQT8'));
    expect(await screen.findByText(/This file is for decision 01M5C5QEHHNXJ3D7X2ZCMGXQT8, not for/)).toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(baselines(stub)).toHaveLength(0);
  });

  it('refuses a file that is not the export, and says why', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp(PAGE);
    await fill(u, JSON.stringify({ baseline_version: 1, salt: 'a'.repeat(64), checks: [] }));
    expect(await screen.findByText(/it holds baseline_export_version, decision_id and fingerprints, and nothing else/)).toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(baselines(stub)).toHaveLength(0);
    // A salted local file is refused by name, so it cannot be uploaded by mistake.
    expect(stub.sent.some((sent) => /salt/.test(sent.body))).toBe(false);
  });

  it('refuses a baseline over 1 MiB with the count and the limit, and sends nothing', async () => {
    const stub = stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    const fit = digestsThatFit('acme/payments');
    await fill(u, exported(digests(fit + 1)));
    expect(await screen.findByText(new RegExp(`holds ${(fit + 1).toLocaleString('en-US')} fingerprints and one request takes at most ${fit.toLocaleString('en-US')} \\(1 MiB\\)`))).toBeInTheDocument();
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(baselines(stub)).toHaveLength(0);
  });

  it('refuses a repository the registry would not store, field by field', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp(PAGE);
    await fill(u, exported(), 'Acme/Payments');
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText(/Write the repository as a lowercase owner\/name/)).toBeInTheDocument();
    expect(baselines(stub)).toHaveLength(0);
  });

  it('asks for the file when none is chosen', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp(PAGE);
    await screen.findByRole('option', { name: /Public ingress terminates TLS/ });
    change('Repository', 'acme/payments');
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText('Choose the file that ipso baseline export wrote.')).toBeInTheDocument();
    expect(baselines(stub)).toHaveLength(0);
  });

  it('refuses a decision that has no EDR id, since no file can name it', async () => {
    stubFetch();
    // A decision that is not in the list of decisions in force has no EDR id to read.
    renderApp('/baselines/new?decision=0194f2a0-0000-7000-8000-0000000009ff');
    await screen.findByRole('heading', { name: 'Record a baseline' });
    await screen.findByRole('option', { name: /Public ingress terminates TLS/ });
    const u = user();
    change('Repository', 'acme/payments');
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText(/not in force or has no EDR id/)).toBeInTheDocument();
  });
});

describe('the file the person chose', () => {
  it('refuses a file over 8 MiB without reading it', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp(PAGE);
    await screen.findByRole('option', { name: /Public ingress terminates TLS/ });
    change('Repository', 'acme/payments');
    const big = new File([new Uint8Array(8 * 1024 * 1024 + 1)], 'big.json', { type: 'application/json' });
    const read = vi.spyOn(big, 'text');
    await u.upload(screen.getByLabelText('Baseline file'), big);
    expect(await screen.findByText(/larger than 8 MiB/)).toBeInTheDocument();
    expect(read).not.toHaveBeenCalled();
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(baselines(stub)).toHaveLength(0);
  });

  it('does not say the file is missing while it is being read, and keeps the file chosen last', async () => {
    const stub = stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    await screen.findByRole('option', { name: /Public ingress terminates TLS/ });
    await waitFor(() => expect(screen.getByLabelText('Decision')).toHaveValue(ids.useTls));
    change('Repository', 'acme/payments');
    // The first file is read slowly and belongs to another decision. The second is read at once.
    let finish: (text: string) => void = () => {};
    const slow = file(exported(digests(3), '01M5C5QEHHNXJ3D7X2ZCMGXQT8'), 'slow.json');
    vi.spyOn(slow, 'text').mockReturnValue(new Promise<string>((resolve) => (finish = resolve)));
    await u.upload(screen.getByLabelText('Baseline file'), slow);
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(screen.queryByText(/Choose the file/)).not.toBeInTheDocument();
    expect(baselines(stub)).toHaveLength(0);

    await u.upload(screen.getByLabelText('Baseline file'), file(exported(digests(2)), 'fast.json'));
    expect(await screen.findByText('fast.json holds 2 fingerprints.')).toBeInTheDocument();
    finish(exported(digests(3), '01M5C5QEHHNXJ3D7X2ZCMGXQT8'));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.getByText('fast.json holds 2 fingerprints.')).toBeInTheDocument();
    expect(screen.queryByText(/This file is for decision/)).not.toBeInTheDocument();
  });
});

describe('what the server answers', () => {
  it('says a 409 means the terms come first and a baseline is recorded once', async () => {
    const stub = stubFetch();
    const u = user();
    renderApp(PAGE);
    await fill(u);
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText(/The decision needs its grandfather terms first/)).toBeInTheDocument();
    expect(screen.getByText(/a recorded baseline cannot be changed/)).toBeInTheDocument();
    expect(baselines(stub)).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Record the baseline' })).toBeEnabled();
    expect(screen.getByLabelText('Repository')).toHaveValue('acme/payments');
  });

  it('answers a second baseline for the same repository with the same words', async () => {
    stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    await fill(u);
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    await screen.findByText('Baseline recorded.');
    await u.click(screen.getByRole('button', { name: 'Record another repository' }));
    await fill(u);
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText(/a recorded baseline cannot be changed/)).toBeInTheDocument();
  });

  it('says in words that no role allows it, and that nothing was stored on a 413', async () => {
    let answer: FixtureReply | undefined = reply(403, 'forbidden');
    stubFetch({ override: ({ method, url }) => (method === 'POST' && url === PATH ? answer : undefined) });
    const u = user();
    renderApp(PAGE);
    await fill(u);
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText('You do not have a role that allows this.')).toBeInTheDocument();
    answer = reply(413, 'too large');
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText(/does not fit in one request \(1 MiB, about 15,600 fingerprints\), so nothing was stored/)).toBeInTheDocument();
    answer = reply(400, 'invalid query');
    await u.click(screen.getByRole('button', { name: 'Record the baseline' }));
    expect(await screen.findByText('Check the repository name and the file.')).toBeInTheDocument();
  });

  it('sends one request on a double click', async () => {
    const stub = stubFetch();
    await recordTerms();
    const u = user();
    renderApp(PAGE);
    await fill(u);
    await u.dblClick(screen.getByRole('button', { name: 'Record the baseline' }));
    await screen.findByText('Baseline recorded.');
    expect(baselines(stub)).toHaveLength(1);
  });
});

describe('the way to the page', () => {
  it('is an action of a decision', async () => {
    stubFetch();
    renderApp(`/decisions/${ids.useTls}`);
    expect(await screen.findByRole('link', { name: 'Record a baseline' })).toHaveAttribute('href', PAGE);
  });

  it('follows a supersession with a baseline or a deadline, and not one with no terms', async () => {
    stubFetch();
    const u = user();
    renderApp('/supersessions/new');
    await screen.findByRole('heading', { name: 'Record a supersession' });
    await u.selectOptions(await screen.findByLabelText('Decision that ends'), ids.pinImages);
    await u.selectOptions(screen.getByLabelText('Decision that replaces it'), ids.useTls);
    await u.click(screen.getByRole('radio', { name: /A baseline with no end/ }));
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    await screen.findByText('Supersession recorded.');
    expect(screen.getByRole('link', { name: 'Record a baseline' })).toHaveAttribute('href', PAGE);
  });

  it('is not offered after a supersession with no terms', async () => {
    stubFetch();
    const u = user();
    renderApp('/supersessions/new');
    await screen.findByRole('heading', { name: 'Record a supersession' });
    await u.selectOptions(await screen.findByLabelText('Decision that ends'), ids.pinImages);
    await u.selectOptions(screen.getByLabelText('Decision that replaces it'), ids.useTls);
    await u.click(screen.getByRole('button', { name: 'Record the supersession' }));
    await screen.findByText('Supersession recorded.');
    expect(screen.queryByRole('link', { name: 'Record a baseline' })).not.toBeInTheDocument();
  });
});
