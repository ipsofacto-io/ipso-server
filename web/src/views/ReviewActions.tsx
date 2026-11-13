import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router';

import { calls } from '../api/calls';
import { useResource, useWrite } from '../api/hooks';
import type { ApprovalRequest, CheckApprovalRequest } from '../api/types';
import { Button, TextField } from '../brand';
import { ErrorNotice } from '../components/ErrorNotice';
import { Loading } from '../components/Loading';
import { useFocusOnMount } from '../components/useFocusOnMount';
import { ScopePicker } from '../components/ScopePicker';
import { SelectField } from '../components/SelectField';
import type { Json } from '../lib/json';
import { aYearAfter, approvalRequest, checkApproval, CRITICALITIES, rejection, slugFrom, today, type ApprovalForm, type Criticality } from '../state/edr';
import { decisionPath } from '../state/decision';
import { draftDefaults, proposalTitle } from '../state/draft';
import { checkAnswer } from '../state/writes';
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
  const { actions, cancel } = useActionsFocus(mode === 'idle');
  const close = () => {
    cancel();
    setMode('idle');
  };

  if (mode === 'approve') {
    return <ApproveForm queue={queue} id={id} title={title} payload={payload} sourceUrl={sourceUrl} report={report} onCancel={close} />;
  }
  if (mode === 'reject') return <RejectConfirm queue={queue} id={id} title={title} report={report} onCancel={close} />;
  return (
    <div className="actions" ref={actions}>
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
  return (
    <Confirm
      label={`Reject ${title}`}
      question="Reject this draft? It leaves the queue and cannot be reopened. Only a person with a role over the whole tenant may reject."
      button="Reject the draft"
      busy="Rejecting"
      variant="danger"
      send={() => decide(queue, id, rejection)}
      success={{ tone: 'info', title: `Rejected "${title}".`, body: 'It left the queue.' }}
      report={report}
      onCancel={onCancel}
    />
  );
}

/**
 * One confirmation and one request, for an answer that cannot be undone. A 409 or a 404 means that the draft was
 * answered or removed under the person, so the queue reads again. Any other refusal stays here, in words. The group
 * takes the focus, because the button that opened it is gone.
 */
function Confirm({
  label,
  question,
  button,
  busy,
  variant,
  send,
  success,
  report,
  onCancel,
}: {
  label: string;
  question: string;
  button: string;
  busy: string;
  variant: 'primary' | 'danger';
  send(): Promise<unknown>;
  success: Report;
  report(report: Report): void;
  onCancel(): void;
}) {
  const write = useWrite(send);
  const group = useFocusOnMount<HTMLDivElement>();

  async function answer() {
    const outcome = await write.run();
    if (outcome.status === 'done') report(success);
    else if (outcome.status === 'failed' && (outcome.error.status === 409 || outcome.error.status === 404)) report(STALE);
  }

  return (
    <div ref={group} tabIndex={-1} className="review" role="group" aria-label={label}>
      <p>{question}</p>
      {write.status === 'failed' ? <ErrorNotice error={write.error} /> : null}
      <div className="actions">
        <Button variant={variant} size="sm" onClick={answer} disabled={write.status === 'sending'}>
          {write.status === 'sending' ? busy : button}
        </Button>
        <Button variant="quiet" size="sm" onClick={onCancel} disabled={write.status === 'sending'}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

/** Where the focus goes after a Cancel: the confirmation that held it is gone, so it returns to the buttons. */
function useActionsFocus(idle: boolean) {
  const actions = useRef<HTMLDivElement>(null);
  const cancelled = useRef(false);
  useEffect(() => {
    if (idle && cancelled.current) {
      cancelled.current = false;
      actions.current?.querySelector('button')?.focus();
    }
  }, [idle]);
  return {
    actions,
    cancel: () => {
      cancelled.current = true;
    },
  };
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

/**
 * Answer one drafted check (ADR-0118). The answer is an outcome and writes no decision, so there is no form: each
 * outcome is one confirmation and one request. Both are final, because a drafted check is answered once, so neither
 * is a single click. Every person sees both buttons and the server decides, as for a draft (ADR-0110 decision 4).
 * `title` names the check as a phrase, such as "the check for decision 0194f2a0, version 2, captured 2026-11-07 11:10 UTC".
 */
export function CheckActions({ decisionId, id, title, report }: { decisionId: string; id: string; title: string; report(report: Report): void }) {
  const [outcome, setOutcome] = useState<CheckApprovalRequest['outcome'] | null>(null);
  const { actions, cancel } = useActionsFocus(outcome === null);
  const close = () => {
    cancel();
    setOutcome(null);
  };
  const send = (answer: CheckApprovalRequest['outcome']) => () => calls.approveCheckProposal(decisionId, id, checkAnswer(answer));

  if (outcome === 'approved') {
    return (
      <Confirm
        label={`Approve ${title}`}
        question="Approve this check? The answer is recorded once and cannot be changed. It writes no decision, and the check reaches no repository yet. Only a person whose role covers every scope of the decision may answer."
        button="Approve the check"
        busy="Approving"
        variant="primary"
        send={send('approved')}
        success={{ tone: 'info', title: `Approved ${title}.`, body: 'It left the queue. The answer is recorded, and the check reaches no repository yet.' }}
        report={report}
        onCancel={close}
      />
    );
  }
  if (outcome === 'rejected') {
    return (
      <Confirm
        label={`Reject ${title}`}
        question="Reject this check? It leaves the queue and cannot be reopened, and the same rule is not drafted again for this version of the decision. Only a person whose role covers every scope of the decision may answer."
        button="Reject the check"
        busy="Rejecting"
        variant="danger"
        send={send('rejected')}
        success={{ tone: 'info', title: `Rejected ${title}.`, body: 'It left the queue.' }}
        report={report}
        onCancel={close}
      />
    );
  }
  return (
    <div className="actions" ref={actions}>
      <Button variant="primary" size="sm" aria-label={`Approve ${title}`} onClick={() => setOutcome('approved')}>
        Approve
      </Button>
      <Button variant="secondary" size="sm" aria-label={`Reject ${title}`} onClick={() => setOutcome('rejected')}>
        Reject
      </Button>
    </div>
  );
}
