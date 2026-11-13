import { useState, type FormEvent } from 'react';
import { Link } from 'react-router';

import { calls } from '../api/calls';
import { useWrite } from '../api/hooks';
import type { PremiseHost, PremiseReason } from '../api/types';
import { Button, TextField } from '../brand';
import { Confirm, useActionsFocus, type Report } from '../components/Confirm';
import { ErrorNotice } from '../components/ErrorNotice';
import { Page } from '../components/Page';
import { Queue, QUEUE_PAGE } from '../components/Queue';
import { ExternalLink } from '../components/Safe';
import { formatTime, shortId } from '../lib/format';
import { decisionPath } from '../state/decision';
import { checkHost, clearance, hostRequest, premiseValue } from '../state/premises';

const INVALID = 'The server refused the host. A host is a DNS name in lowercase ASCII, with no scheme, port or path, in punycode when it is not ASCII, and never an address.';

/** A reason cleared or removed under the person: say so, and read the list again. */
const CLEARED_FIRST: Report = {
  tone: 'error',
  title: 'This reason was already cleared.',
  body: 'Someone cleared it first, or it no longer exists. The list was read again.',
};

/**
 * Clear one reason (ADR-0119). A clearance records that an owner looked and has no field, so it is one confirmation and
 * one request. Every person sees the button and the server decides, because no route says what role a person holds.
 */
function ClearAction({ reason, report }: { reason: PremiseReason; report(report: Report): void }) {
  const [asking, setAsking] = useState(false);
  const { actions, cancel } = useActionsFocus(!asking);
  // The premise and the full id of its decision are the key of an open reason, and the path of the clearance names them, so no two names are alike.
  const name = `the review reason of premise ${reason.premise_id} of decision ${reason.decision_id}`;

  if (asking) {
    return (
      <Confirm
        label={`Clear ${name}`}
        question="Clear this reason? It records that an owner looked at the premise and cannot be undone. It does not change the decision, and no probe runs now: if the premise fails again, a new reason opens. Only a person whose role covers every scope of the decision may clear it."
        button="Clear the reason"
        busy="Clearing"
        variant="primary"
        send={() => calls.clearPremiseReason(reason.decision_id, reason.premise_id, clearance())}
        success={{ tone: 'info', title: `Cleared ${name}.`, body: 'It left the list. The next probe of the premise decides whether a new reason opens.' }}
        stale={CLEARED_FIRST}
        report={report}
        onCancel={() => {
          cancel();
          setAsking(false);
        }}
      />
    );
  }
  return (
    <div className="actions" ref={actions}>
      <Button variant="primary" size="sm" aria-label={`Clear ${name}`} onClick={() => setAsking(true)}>
        Clear
      </Button>
    </div>
  );
}

function Reason({ reason, report }: { reason: PremiseReason; report(report: Report): void }) {
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{`Premise ${reason.premise_id}`}</h3>
      </header>
      <dl className="meta">
        <div>
          <dt>Decision</dt>
          <dd>
            <Link to={decisionPath(reason.decision_id)} className="mono">
              {shortId(reason.decision_id)}
            </Link>
          </dd>
        </div>
        <div>
          <dt>Opened</dt>
          <dd className="mono">{formatTime(reason.opened_at)}</dd>
        </div>
        <div>
          <dt>URL</dt>
          <dd>
            <ExternalLink href={reason.url}>{reason.url}</ExternalLink>
          </dd>
        </div>
        <div>
          <dt>Pointer</dt>
          <dd className="mono">{reason.pointer}</dd>
        </div>
        <div>
          <dt>Expected</dt>
          <dd className="mono">{premiseValue(reason.expected)}</dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd className="mono">{premiseValue(reason.observed)}</dd>
        </div>
      </dl>
      <p className="muted">The observed value was read from a public URL, so it is shown as text and nothing in it is run.</p>
      <ClearAction reason={reason} report={report} />
    </>
  );
}

/** One host of the allowlist, as its latest row says. An allow and a withdraw undo each other, so neither confirms. */
function HostRow({ host, report }: { host: PremiseHost; report(report: Report): void }) {
  const write = useWrite((allowed: boolean) => calls.allowPremiseHost(hostRequest(host.host, allowed)));
  const sending = write.status === 'sending';

  async function change(allowed: boolean) {
    const outcome = await write.run(allowed);
    if (outcome.status === 'done') {
      report({
        tone: 'info',
        title: allowed ? `Allowed ${host.host}.` : `Withdrew ${host.host}.`,
        body: allowed ? 'A premise probe may dial it from its next run.' : 'A premise probe no longer dials it. It stays listed so it can be allowed again.',
      });
    }
  }

  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{host.host}</h3>
        <span className={host.allowed ? 'state-label' : 'state-label state-none'}>{host.allowed ? 'Allowed' : 'Withdrawn'}</span>
      </header>
      {write.status === 'failed' ? <ErrorNotice error={write.error} invalid={INVALID} /> : null}
      <div className="actions">
        <Button
          variant={host.allowed ? 'secondary' : 'primary'}
          size="sm"
          aria-label={host.allowed ? `Withdraw ${host.host}` : `Allow again ${host.host}`}
          disabled={sending}
          onClick={() => void change(!host.allowed)}
        >
          {sending ? (host.allowed ? 'Withdrawing' : 'Allowing') : host.allowed ? 'Withdraw' : 'Allow again'}
        </Button>
      </div>
    </>
  );
}

/** Allows a host. The field is checked as the server checks a host, and the server stays the authority. */
function AllowForm({ report }: { report(report: Report): void }) {
  const write = useWrite((host: string) => calls.allowPremiseHost(hostRequest(host, true)));
  const [value, setValue] = useState('');
  const [tried, setTried] = useState(false);
  const check = checkHost(value);
  const sending = write.status === 'sending';

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (!check.ok) return;
    const outcome = await write.run(check.host);
    if (outcome.status === 'done') {
      setValue('');
      setTried(false);
      report({ tone: 'info', title: `Allowed ${check.host}.`, body: 'A premise probe may dial it from its next run.' });
    }
  }

  return (
    <>
      <form className="form" onSubmit={submit} noValidate aria-label="Allow a host">
        <fieldset className="fieldset" disabled={sending}>
          <legend className="ip-label">Allow a host</legend>
          <TextField
            label="Host"
            mono
            autoComplete="off"
            spellCheck={false}
            value={value}
            error={tried && !check.ok ? check.error : undefined}
            hint="A DNS name such as status.example.com, with no scheme, port or path."
            onChange={(event) => setValue(event.target.value)}
          />
        </fieldset>
        <div className="actions">
          <Button type="submit" variant="primary" disabled={sending}>
            {sending ? 'Allowing' : 'Allow the host'}
          </Button>
        </div>
      </form>
      {write.status === 'failed' ? <ErrorNotice error={write.error} invalid={INVALID} /> : null}
    </>
  );
}

/**
 * The open review reasons of the premises, and the hosts a premise probe may dial (ADR-0119). A person with any role
 * reads both. Clearing a reason and changing the allowlist are the server's to allow, so the app shows the actions to
 * every person whose read was not refused and says in words what a refusal means.
 */
export function PremisesView() {
  return (
    <Page title="Premises" intro="Why a premise of a decision failed its probe, and the hosts a probe may dial. A reason stays open until a person clears it.">
      <Queue
        title="Open review reasons"
        intro="A fail opens a reason and it stays open, even when its decision is no longer in force, until a person clears it. Only a decision owner whose role covers every scope of the decision may clear one."
        empty="No review reason is open."
        load={async (before, signal) => (await calls.listPremiseReasons({ limit: QUEUE_PAGE, before }, signal)).premise_reasons}
      >
        {(reason, report) => <Reason reason={reason} report={report} />}
      </Queue>
      <Queue
        title="Allowlist"
        intro="A probe dials only a host on this list, and the latest row of a host decides. A withdrawn host stays listed so it can be allowed again, so a list of withdrawn hosts means that no host is allowed. Only an admin may change it."
        empty="No host is allowed, so no probe can dial one."
        load={async (before, signal) => (await calls.listPremiseHosts({ limit: QUEUE_PAGE, before }, signal)).premise_hosts}
        head={(report) => <AllowForm report={report} />}
      >
        {(host, report) => <HostRow host={host} report={report} />}
      </Queue>
    </Page>
  );
}
