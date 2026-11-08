import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router';

import { calls } from '../api/calls';
import { useResource, useWrite } from '../api/hooks';
import type { ApprovalRequest } from '../api/types';
import { Button, TextField } from '../brand';
import { ErrorNotice } from '../components/ErrorNotice';
import { Loading } from '../components/Loading';
import { ScopePicker } from '../components/ScopePicker';
import { SelectField } from '../components/SelectField';
import type { Json } from '../lib/json';
import { aYearAfter, approvalRequest, checkApproval, CRITICALITIES, rejection, slugFrom, today, type ApprovalForm, type Criticality } from '../state/edr';
import { decisionPath } from '../state/decision';
import { draftDefaults, proposalTitle } from '../state/draft';
import { scopesForLabels } from './Scopes';

export type Queue = 'proposals' | 'agent-proposals';

/** What a queue says above its cards after a write, and the reason it reads the queue again. */
export interface Report {
  tone: 'info' | 'error';
  title: string;
  body?: ReactNode;
}

type Mode = 'idle' | 'approve' | 'reject';

function decide(queue: Queue, id: string, request: ApprovalRequest) {
  return queue === 'proposals' ? calls.approveProposal(id, request) : calls.approveAgentProposal(id, request);
}

/** A draft that was answered or removed under the person: say so, and read the queue again. */
const STALE: Report = {
  tone: 'error',
  title: 'This draft was already answered.',
  body: 'Someone answered it first, or it no longer exists. The queue was read again.',
};

/**
 * Approve or reject one draft. Approving writes the decision the person confirms below, and rejecting is one
 * more click. Neither is optimistic: the queue reads again and the draft leaves it only if the server says so
 * (ADR-0110). Every person sees both, because no route says what role they hold, and a 403 says it in words.
 */
export function ReviewActions({
  queue,
  id,
  payload,
  sourceUrl,
  report,
}: {
  queue: Queue;
  id: string;
  payload: Json;
  sourceUrl?: unknown;
  report(report: Report): void;
}) {
  const [mode, setMode] = useState<Mode>('idle');
  const title = proposalTitle(payload);
  const close = () => setMode('idle');

  if (mode === 'approve') {
    return <ApproveForm queue={queue} id={id} title={title} payload={payload} sourceUrl={sourceUrl} report={report} onCancel={close} />;
  }
  if (mode === 'reject') return <RejectConfirm queue={queue} id={id} title={title} report={report} onCancel={close} />;
  return (
    <div className="actions">
      <Button variant="primary" size="sm" aria-label={`Approve ${title}`} onClick={() => setMode('approve')}>
        Approve
      </Button>
      <Button variant="secondary" size="sm" aria-label={`Reject ${title}`} onClick={() => setMode('reject')}>
        Reject
      </Button>
    </div>
  );
}

function RejectConfirm({ queue, id, title, report, onCancel }: { queue: Queue; id: string; title: string; report(report: Report): void; onCancel(): void }) {
  const write = useWrite((request: ApprovalRequest) => decide(queue, id, request));

  async function reject() {
    const outcome = await write.run(rejection);
    if (outcome.status === 'done') report({ tone: 'info', title: `Rejected "${title}".`, body: 'It left the queue.' });
    else if (outcome.status === 'failed' && (outcome.error.status === 409 || outcome.error.status === 404)) report(STALE);
  }

  return (
    <div className="review" role="group" aria-label={`Reject ${title}`}>
      <p>Reject this draft? It leaves the queue and cannot be reopened. Only a person with a role over the whole tenant may reject.</p>
      {write.status === 'failed' ? <ErrorNotice error={write.error} /> : null}
      <div className="actions">
        <Button variant="danger" size="sm" onClick={reject} disabled={write.status === 'sending'}>
          {write.status === 'sending' ? 'Rejecting' : 'Reject the draft'}
        </Button>
        <Button variant="quiet" size="sm" onClick={onCancel} disabled={write.status === 'sending'}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

function ApproveForm({
  queue,
  id,
  title: draftName,
  payload,
  sourceUrl,
  report,
  onCancel,
}: {
  queue: Queue;
  id: string;
  title: string;
  payload: Json;
  sourceUrl: unknown;
  report(report: Report): void;
  onCancel(): void;
}) {
  const defaults = draftDefaults(payload, sourceUrl);
  const scopes = useResource((signal) => scopesForLabels(signal), []);
  const write = useWrite((request: ApprovalRequest) => decide(queue, id, request));
  const root = useRef<HTMLFormElement>(null);

  const [form, setForm] = useState<ApprovalForm>(() => {
    const start = today();
    return {
      title: defaults.title,
      slug: defaults.slug,
      owner: '',
      criticality: defaults.criticality,
      validFrom: start,
      reviewBy: aYearAfter(start),
      sourceUrl: defaults.sourceUrl,
      sourceType: queue === 'proposals' ? 'pr' : 'note',
    };
  });
  const [picked, setPicked] = useState<string[]>([]);
  const [tried, setTried] = useState(false);
  // A field the person has typed in stops following the one it is derived from.
  const [touched, setTouched] = useState({ slug: false, reviewBy: false });

  useEffect(() => {
    root.current?.querySelector('input')?.focus();
  }, []);

  const errors = checkApproval(form, picked);
  const shown = tried ? errors : {};
  const set = <K extends keyof ApprovalForm>(key: K, value: ApprovalForm[K]) => setForm((current) => ({ ...current, [key]: value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (Object.keys(errors).length > 0 || scopes.status !== 'ready') return;
    const outcome = await write.run(approvalRequest(form, picked, scopes.data));
    if (outcome.status === 'done') {
      const decision = outcome.result.decision_id;
      report({
        tone: 'info',
        title: `Approved "${form.title}".`,
        body: decision ? <Link to={decisionPath(decision)}>Open the decision</Link> : undefined,
      });
    } else if (outcome.status === 'failed' && (outcome.error.status === 409 || outcome.error.status === 404)) {
      report(STALE);
    }
  }

  const sending = write.status === 'sending';
  return (
    <form ref={root} className="review" onSubmit={submit} noValidate aria-label={`Approve ${draftName}`}>
      <p className="muted">Approving records this draft as a decision that starts on the date below. Read it, then fill in what the draft does not say.</p>
      {defaults.statement ? (
        <div>
          <h4 className="ip-label">Statement</h4>
          <p className="statement">{defaults.statement}</p>
        </div>
      ) : null}
      {defaults.rationale ? (
        <div>
          <h4 className="ip-label">Rationale</h4>
          <p className="statement">{defaults.rationale}</p>
        </div>
      ) : null}
      <fieldset className="fieldset" disabled={sending}>
        <legend className="ip-label">The decision</legend>
        <div className="form-row">
          <TextField
            label="Title"
            value={form.title}
            error={shown.title}
            onChange={(event) => {
              set('title', event.target.value);
              if (!touched.slug) set('slug', slugFrom(event.target.value));
            }}
          />
          <TextField
            label="Slug"
            mono
            value={form.slug}
            error={shown.slug}
            hint="Lowercase words joined by hyphens."
            onChange={(event) => {
              setTouched((current) => ({ ...current, slug: true }));
              set('slug', event.target.value);
            }}
          />
        </div>
        <div className="form-row">
          <TextField label="Owner" mono value={form.owner} error={shown.owner} placeholder="team:platform" hint="The team that answers for it." onChange={(event) => set('owner', event.target.value)} />
          <SelectField label="Criticality" value={form.criticality} onChange={(event) => set('criticality', event.target.value as Criticality)}>
            {CRITICALITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </SelectField>
        </div>
        <div className="form-row">
          <TextField
            label="Starts"
            type="date"
            value={form.validFrom}
            error={shown.validFrom}
            hint="A date, in UTC."
            onChange={(event) => {
              set('validFrom', event.target.value);
              if (!touched.reviewBy) set('reviewBy', aYearAfter(event.target.value));
            }}
          />
          <TextField
            label="Review by"
            type="date"
            value={form.reviewBy}
            error={shown.reviewBy}
            hint="When someone looks at it again."
            onChange={(event) => {
              setTouched((current) => ({ ...current, reviewBy: true }));
              set('reviewBy', event.target.value);
            }}
          />
        </div>
        <TextField
          label="Source"
          mono
          value={form.sourceUrl}
          error={shown.sourceUrl}
          hint={queue === 'proposals' ? 'The pull request it came from.' : 'An https link to where the agent found it.'}
          onChange={(event) => set('sourceUrl', event.target.value)}
        />
      </fieldset>
      {scopes.status === 'loading' ? <Loading what="scopes" /> : null}
      {scopes.status === 'error' ? <ErrorNotice error={scopes.error} onRetry={scopes.reload} /> : null}
      {scopes.status === 'ready' ? (
        <ScopePicker legend="Scopes" hint="The decision applies to each scope you pick and everything under it." scopes={scopes.data} selected={picked} onChange={setPicked} error={shown.scopes} />
      ) : null}
      {write.status === 'failed' ? <ErrorNotice error={write.error} invalid="Check the slug and that every scope still exists." /> : null}
      <div className="actions">
        <Button type="submit" variant="primary" disabled={sending || scopes.status !== 'ready'}>
          {sending ? 'Approving' : 'Approve and record the decision'}
        </Button>
        <Button variant="quiet" onClick={onCancel} disabled={sending}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
