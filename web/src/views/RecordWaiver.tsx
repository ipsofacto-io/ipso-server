import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';

import { calls } from '../api/calls';
import { useResource, useWrite } from '../api/hooks';
import type { WaiverRequest } from '../api/types';
import { Button, TextField } from '../brand';
import { DecisionPicker, loadAllDecisions } from '../components/DecisionPicker';
import { ErrorNotice } from '../components/ErrorNotice';
import { LinkButton } from '../components/LinkButton';
import { Loading } from '../components/Loading';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { ScopePicker } from '../components/ScopePicker';
import { useFocusOnMount } from '../components/useFocusOnMount';
import { formatTime, nowForField } from '../lib/format';
import { checkWaiver, REASON_MAX, TICKET_MAX, waiverRequest, WAIVER_MAX_DAYS, type WaiverForm } from '../state/writes';
import { scopesForLabels } from './Scopes';

const TITLE = 'Record a waiver';
const CONFLICT =
  'The scope must be one of the decision\'s scopes or sit under one, and the period must fall inside a version of the decision that is in force. Check the decision, the scope and both times.';

function blank(decision: string): WaiverForm {
  return { decisionId: decision, scopeId: '', reason: '', ticket: '', startsAt: nowForField(), endsAt: '' };
}

/**
 * A waiver lets one scope break a decision for a while (ADR-0054). A person records it, and the role policy
 * refuses an agent before the server reads the body (ADR-0109). The approver is the person signed in, and the
 * form has no field for it.
 */
export function RecordWaiverView() {
  const [params] = useSearchParams();
  const decisions = useResource((signal) => loadAllDecisions(signal), []);
  const scopes = useResource((signal) => scopesForLabels(signal), []);
  const write = useWrite((request: WaiverRequest) => calls.recordWaiver(request));
  const [form, setForm] = useState<WaiverForm>(() => blank(params.get('decision') ?? ''));
  const [tried, setTried] = useState(false);
  const done = useFocusOnMount<HTMLDivElement>();

  const errors = checkWaiver(form);
  const shown = tried ? errors : {};
  const set = <K extends keyof WaiverForm>(key: K, value: WaiverForm[K]) => setForm((current) => ({ ...current, [key]: value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (Object.keys(errors).length > 0) return;
    await write.run(waiverRequest(form));
  }

  function again() {
    setForm(blank(''));
    setTried(false);
    write.reset();
  }

  if (write.status === 'done') {
    const scope = scopes.status === 'ready' ? scopes.data.find((candidate) => candidate.id === write.result.scope_id) : undefined;
    return (
      <Page title={TITLE}>
        <div ref={done} tabIndex={-1}>
          <Notice title="Waiver recorded.">
            <p>
              {write.result.ticket_ref} covers {scope ? `${scope.kind} ${scope.selector}` : 'the scope'} until {formatTime(write.result.expires_at)}.
            </p>
          </Notice>
        </div>
        <div className="actions">
          <LinkButton to="/waivers" variant="primary">
            See the waivers
          </LinkButton>
          <Button onClick={again}>Record another</Button>
        </div>
      </Page>
    );
  }

  const sending = write.status === 'sending';
  return (
    <Page title={TITLE} intro={`A waiver lets one scope break a decision for at most ${WAIVER_MAX_DAYS} days, and it ends on its own. A person records it: a coding agent cannot.`}>
      {decisions.status === 'loading' || scopes.status === 'loading' ? <Loading what="decisions and scopes" /> : null}
      {decisions.status === 'error' ? <ErrorNotice error={decisions.error} onRetry={decisions.reload} /> : null}
      {scopes.status === 'error' ? <ErrorNotice error={scopes.error} onRetry={scopes.reload} /> : null}
      {decisions.status === 'ready' && scopes.status === 'ready' ? (
        <form className="form" onSubmit={submit} noValidate>
          <DecisionPicker label="Decision" decisions={decisions.data} value={form.decisionId} error={shown.decisionId} onChange={(value) => set('decisionId', value)} disabled={sending} />
          <ScopePicker
            legend="Scope"
            hint="The one scope that may break the decision. It must be one of the decision's scopes or sit under one."
            scopes={scopes.data}
            selected={form.scopeId ? [form.scopeId] : []}
            onChange={(next) => set('scopeId', next[0] ?? '')}
            one
            error={shown.scopeId}
          />
          <fieldset className="fieldset" disabled={sending}>
            <legend className="ip-label">Why and until when</legend>
            <TextField label="Reason" value={form.reason} error={shown.reason} hint={`Up to ${REASON_MAX} characters, on one line.`} onChange={(event) => set('reason', event.target.value)} />
            <TextField label="Ticket" mono value={form.ticket} error={shown.ticket} hint={`The ticket that tracks the fix. Up to ${TICKET_MAX} characters.`} onChange={(event) => set('ticket', event.target.value)} />
            <div className="form-row">
              <TextField label="Starts" type="datetime-local" value={form.startsAt} error={shown.startsAt} hint="In UTC, to the minute." onChange={(event) => set('startsAt', event.target.value)} />
              <TextField label="Ends" type="datetime-local" value={form.endsAt} error={shown.endsAt} hint={`At most ${WAIVER_MAX_DAYS} days after it starts.`} onChange={(event) => set('endsAt', event.target.value)} />
            </div>
          </fieldset>
          {write.status === 'failed' ? <ErrorNotice error={write.error} conflict={CONFLICT} invalid="Check the reason, the ticket and the times." /> : null}
          <div className="actions">
            <Button type="submit" variant="primary" disabled={sending}>
              {sending ? 'Recording' : 'Record the waiver'}
            </Button>
            <LinkButton to="/waivers" variant="quiet">
              Cancel
            </LinkButton>
          </div>
        </form>
      ) : null}
    </Page>
  );
}
