import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';

import { calls } from '../api/calls';
import { useResource, useWrite } from '../api/hooks';
import type { Decision, GrandfatherRequest, SupersessionRequest } from '../api/types';
import { Button, TextField } from '../brand';
import { DecisionPicker, loadAllDecisions } from '../components/DecisionPicker';
import { ErrorNotice } from '../components/ErrorNotice';
import { LinkButton } from '../components/LinkButton';
import { Loading } from '../components/Loading';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { useFocusOnMount } from '../components/useFocusOnMount';
import { fieldToTime, formatTime, nowForField, shortId } from '../lib/format';
import { asString } from '../lib/json';
import { decisionPath } from '../state/decision';
import { checkSupersession, grandfatherRequest, supersessionRequest, type SupersessionForm, type Terms } from '../state/writes';

const TITLE = 'Record a supersession';
const SUPERSESSION_CONFLICT =
  'The old decision needs a version in force that started by then, the new one must be in force at that time, and neither may already be superseded. Check both decisions and the time.';
const TERMS_CONFLICT = 'The new decision may already have grandfather terms, and a decision has one set. A recorded set cannot be changed.';

const TERMS: { value: Terms; label: string }[] = [
  { value: 'none', label: 'None. Code that breaks the new decision fails as soon as it starts.' },
  { value: 'baseline', label: 'A baseline with no end. Violations in a recorded baseline are tolerated until they are fixed.' },
  { value: 'deadline', label: 'A deadline. Violations in a recorded baseline are tolerated until the date below.' },
];

function blank(from: string, to: string): SupersessionForm {
  return { fromId: from, toId: to, effectiveAt: nowForField(), terms: 'none', deadline: '' };
}

function nameOf(decisions: readonly Decision[], id: string): string {
  const found = decisions.find((decision) => decision.id === id);
  return (found && (asString(found.body.title) ?? asString(found.body.slug))) ?? `decision ${shortId(id)}`;
}

/**
 * A new decision replaces an old one from an instant (ADR-0052). Recording it closes the old decision at that
 * instant, and the new decision may carry grandfather terms. The supersession is sent first, so a refusal of it
 * writes nothing. When the terms are refused after it was recorded, the page says so and sends only the terms
 * again, because the supersession cannot be recorded twice.
 */
export function RecordSupersessionView() {
  const [params] = useSearchParams();
  const decisions = useResource((signal) => loadAllDecisions(signal), []);
  const supersession = useWrite((request: SupersessionRequest) => calls.recordSupersession(request));
  const terms = useWrite((to: string, request: GrandfatherRequest) => calls.recordGrandfatherPeriod(to, request));
  const [form, setForm] = useState<SupersessionForm>(() => blank(params.get('from') ?? '', params.get('to') ?? ''));
  const [tried, setTried] = useState(false);
  const done = useFocusOnMount<HTMLDivElement>();

  const errors = checkSupersession(form);
  const shown = tried ? errors : {};
  const set = <K extends keyof SupersessionForm>(key: K, value: SupersessionForm[K]) => setForm((current) => ({ ...current, [key]: value }));

  const recorded = supersession.status === 'done';
  const sending = supersession.status === 'sending' || terms.status === 'sending';
  const finished = recorded && (form.terms === 'none' || terms.status === 'done');

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (Object.keys(errors).length > 0) return;
    if (!recorded) {
      const outcome = await supersession.run(supersessionRequest(form));
      if (outcome.status !== 'done') return;
    }
    const request = grandfatherRequest(form);
    if (request) await terms.run(form.toId, request);
  }

  function again() {
    setForm(blank('', ''));
    setTried(false);
    supersession.reset();
    terms.reset();
  }

  if (finished && supersession.status === 'done') {
    const all = decisions.status === 'ready' ? decisions.data : [];
    const { effective_at: at } = supersession.result;
    return (
      <Page title={TITLE}>
        <div ref={done} tabIndex={-1}>
          <Notice title="Supersession recorded.">
            <p>
              {nameOf(all, form.fromId)} is superseded by {nameOf(all, form.toId)} from {formatTime(at)}.
            </p>
            <p>
              {form.terms === 'none' ? 'No grandfather terms were recorded.' : null}
              {form.terms === 'baseline' ? 'Grandfather terms were recorded with no end.' : null}
              {form.terms === 'deadline' ? `Grandfather terms were recorded until ${formatTime(fieldToTime(form.deadline))}.` : null}
            </p>
            {form.terms === 'none' ? null : <p>The terms apply to the baseline of each repository, which is recorded from the new decision.</p>}
          </Notice>
        </div>
        <div className="actions">
          <LinkButton to={decisionPath(form.toId)} variant="primary">
            Open the new decision
          </LinkButton>
          {form.terms === 'none' ? null : <LinkButton to={`/baselines/new?decision=${encodeURIComponent(form.toId)}`}>Record a baseline</LinkButton>}
          <LinkButton to={decisionPath(form.fromId)}>Open the old decision</LinkButton>
          <Button onClick={again}>Record another</Button>
        </div>
      </Page>
    );
  }

  const locked = sending || recorded;
  return (
    <Page title={TITLE} intro="A new decision replaces an old one from a time. The old decision stops being in force at that instant.">
      {decisions.status === 'loading' ? <Loading what="decisions" /> : null}
      {decisions.status === 'error' ? <ErrorNotice error={decisions.error} onRetry={decisions.reload} /> : null}
      {decisions.status === 'ready' ? (
        <form className="form" onSubmit={submit} noValidate>
          <fieldset className="fieldset" disabled={locked}>
            <legend className="ip-label">The two decisions</legend>
            <DecisionPicker label="Decision that ends" decisions={decisions.data} value={form.fromId} error={shown.fromId} onChange={(value) => set('fromId', value)} />
            <DecisionPicker label="Decision that replaces it" decisions={decisions.data} value={form.toId} error={shown.toId} onChange={(value) => set('toId', value)} />
            <TextField label="From" type="datetime-local" value={form.effectiveAt} error={shown.effectiveAt} hint="In UTC, to the minute. The new decision must be in force then." onChange={(event) => set('effectiveAt', event.target.value)} />
          </fieldset>
          <fieldset className="fieldset" disabled={locked}>
            <legend className="ip-label">Code that already breaks the new decision</legend>
            {TERMS.map((option) => (
              <label key={option.value} className="choice">
                <input type="radio" name="terms" value={option.value} checked={form.terms === option.value} onChange={() => set('terms', option.value)} />
                <span>{option.label}</span>
              </label>
            ))}
            {form.terms === 'deadline' ? (
              <TextField label="Deadline" type="datetime-local" value={form.deadline} error={shown.deadline} hint="In UTC, to the minute. It comes after the supersession starts." onChange={(event) => set('deadline', event.target.value)} />
            ) : null}
            <p className="muted">These terms say how long a recorded baseline counts, and a decision has one set. The baseline of each repository is recorded afterwards, from the decision.</p>
          </fieldset>

          {supersession.status === 'failed' ? <ErrorNotice error={supersession.error} conflict={SUPERSESSION_CONFLICT} invalid="Check both decisions and the time." /> : null}
          {recorded ? (
            <Notice tone="error" title="The supersession is recorded, but the grandfather terms are not.">
              <p>Send the terms again. The supersession is not sent twice.</p>
            </Notice>
          ) : null}
          {terms.status === 'failed' ? <ErrorNotice error={terms.error} conflict={TERMS_CONFLICT} invalid="Check the deadline." /> : null}

          {recorded ? null : (
            <p>
              <strong>This cannot be undone from the app.</strong> The old decision stops being in force at that time, and no route removes a recorded supersession.
            </p>
          )}
          <div className="actions">
            <Button type="submit" variant="primary" disabled={sending}>
              {sending ? 'Recording' : recorded ? 'Record the grandfather terms' : 'Record the supersession'}
            </Button>
            {recorded ? (
              <LinkButton to={decisionPath(form.toId)} variant="quiet">
                Leave without the terms
              </LinkButton>
            ) : (
              <LinkButton to="/decisions" variant="quiet">
                Cancel
              </LinkButton>
            )}
          </div>
        </form>
      ) : null}
    </Page>
  );
}
