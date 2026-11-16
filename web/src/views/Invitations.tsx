import { useState, type FormEvent } from 'react';

import { calls } from '../api/calls';
import { useWrite } from '../api/hooks';
import type { Invitation, InvitationRole } from '../api/types';
import { useApp } from '../app/AppContext';
import { Button, TextField } from '../brand';
import { Confirm, useActionsFocus, type Report } from '../components/Confirm';
import { ErrorNotice } from '../components/ErrorNotice';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { Queue, QUEUE_PAGE } from '../components/Queue';
import { SelectField } from '../components/SelectField';
import { formatTime } from '../lib/format';
import { notRefused } from '../state/export';
import { checkName, CREATE_CONFLICT, CREATE_INVALID, INVITATION_ROLES, roleLabel } from '../state/invitations';
import { expiry } from './Waivers';

/** An invitation that was used, revoked or has expired under the person: say so, and read the list again. */
const GONE_FIRST: Report = {
  tone: 'error',
  title: 'This invitation is already gone.',
  body: 'It was used, revoked or has expired. The list was read again.',
};

/** The link the answer to create holds, kept only for as long as this form is on the page. */
interface Link {
  name: string;
  role: InvitationRole;
  expiresAt: string;
  url: string;
}

type Copied = 'idle' | 'copied' | 'failed';

/**
 * The link of a new invitation (ADR-0127). The server keeps only the SHA-256 of the token, so this is the one time
 * the link exists. It is text in a read-only field and never an anchor, so opening it here does not start a sign-in
 * as the person it was made for, and it is held in this component and nowhere else: not in the list, the address or
 * the storage of the browser.
 */
function LinkPanel({ link, onHide }: { link: Link; onHide(): void }) {
  const [copied, setCopied] = useState<Copied>('idle');

  async function copy() {
    try {
      await navigator.clipboard.writeText(link.url);
      setCopied('copied');
    } catch {
      setCopied('failed');
    }
  }

  return (
    <section className="card" aria-labelledby="invitation-link">
      <h3 id="invitation-link" className="card-title">
        {`Link for ${link.name}`}
      </h3>
      <Notice title="This link is shown once.">
        <p>
          The server keeps no copy, so a link you lose is revoked and made again. Whoever opens it and signs in first becomes {link.name} with the role{' '}
          {roleLabel(link.role)}. It works until {formatTime(link.expiresAt)}, or until you revoke it. Send it by a channel the person controls: ipso sends no email.
        </p>
      </Notice>
      <TextField
        label="Invitation link"
        className="link-field"
        mono
        readOnly
        autoComplete="off"
        spellCheck={false}
        value={link.url}
        onFocus={(event) => event.currentTarget.select()}
      />
      <div className="actions">
        <Button variant="primary" onClick={() => void copy()}>
          Copy the link
        </Button>
        <Button variant="quiet" onClick={onHide}>
          Hide the link
        </Button>
      </div>
      {copied === 'copied' ? <p className="muted" role="status">Copied.</p> : null}
      {copied === 'failed' ? (
        <p className="muted" role="alert">
          The browser did not allow the copy. Select the link in the field and copy it yourself.
        </p>
      ) : null}
    </section>
  );
}

/** Invites a person from a name and one role. The body is only those two: the tenant and the inviter come from the session. */
function InviteForm({ report }: { report(report: Report): void }) {
  const write = useWrite((name: string, role: InvitationRole) => calls.createInvitation({ name, role }));
  const [name, setName] = useState('');
  const [role, setRole] = useState<InvitationRole>('viewer');
  const [tried, setTried] = useState(false);
  const [link, setLink] = useState<Link | null>(null);
  const check = checkName(name);
  const sending = write.status === 'sending';

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (!check.ok) return;
    const outcome = await write.run(check.name, role);
    if (outcome.status === 'done') {
      const made = outcome.result;
      // The token is dropped here: the link holds it, and nothing else of this component needs it.
      setLink({ name: made.name, role: made.role, expiresAt: made.expires_at, url: made.url });
      setName('');
      setTried(false);
      report({ tone: 'info', title: `Invited ${made.name}.`, body: 'Copy the link below now. It is shown once.' });
    }
  }

  return (
    <>
      {link ? <LinkPanel link={link} onHide={() => setLink(null)} /> : null}
      <form className="form" onSubmit={submit} noValidate aria-label="Invite a person">
        <fieldset className="fieldset" disabled={sending}>
          <legend className="ip-label">Invite a person</legend>
          <TextField
            label="Name"
            autoComplete="off"
            value={name}
            error={tried && !check.ok ? check.error : undefined}
            hint="What ipso calls the person. It does not have to match their account, and ipso keeps no email address."
            onChange={(event) => setName(event.target.value)}
          />
          <SelectField
            label="Role"
            hint="The one role the person gets, over the whole tenant."
            value={role}
            onChange={(event) => setRole(event.target.value as InvitationRole)}
          >
            {INVITATION_ROLES.map((option) => (
              <option key={option} value={option}>
                {roleLabel(option)}
              </option>
            ))}
          </SelectField>
        </fieldset>
        <div className="actions">
          <Button type="submit" variant="primary" disabled={sending}>
            {sending ? 'Inviting' : 'Invite the person'}
          </Button>
        </div>
      </form>
      {write.status === 'failed' ? <ErrorNotice error={write.error} conflict={CREATE_CONFLICT} invalid={CREATE_INVALID} /> : null}
    </>
  );
}

/** Revokes one invitation, so its link stops working. It cannot be undone, so it is one confirmation and one request. */
function RevokeAction({ invitation, report }: { invitation: Invitation; report(report: Report): void }) {
  const [asking, setAsking] = useState(false);
  const { actions, cancel } = useActionsFocus(!asking);
  // The start of a UUIDv7 is the time it was made, so two invitations of one minute share it: the end tells them apart.
  const name = `the invitation of ${invitation.name} (${roleLabel(invitation.role)}, ${invitation.id.slice(-8)})`;

  if (asking) {
    return (
      <Confirm
        label={`Revoke ${name}`}
        question="Revoke this invitation? Its link stops working at once and cannot be made to work again. Make a new invitation to invite the person after that."
        button="Revoke the invitation"
        busy="Revoking"
        variant="danger"
        send={() => calls.revokeInvitation(invitation.id)}
        success={{ tone: 'info', title: `Revoked ${name}.`, body: 'Its link no longer works.' }}
        stale={GONE_FIRST}
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
      <Button variant="secondary" size="sm" aria-label={`Revoke ${name}`} onClick={() => setAsking(true)}>
        Revoke
      </Button>
    </div>
  );
}

function OpenInvitation({ invitation, report }: { invitation: Invitation; report(report: Report): void }) {
  const end = expiry(invitation.expires_at, new Date());
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{invitation.name}</h3>
        <span className="state-label">{roleLabel(invitation.role)}</span>
      </header>
      <dl className="meta">
        <div>
          <dt>Made</dt>
          <dd className="mono">{formatTime(invitation.created_at)}</dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>
            <span className={end.soon ? 'deadline deadline-soon' : 'deadline'}>{end.text}</span>
            <div className="muted mono">{formatTime(invitation.expires_at)}</div>
          </dd>
        </div>
        <div>
          <dt>Made by</dt>
          <dd className="mono">{invitation.created_by}</dd>
        </div>
      </dl>
      <RevokeAction invitation={invitation} report={report} />
    </>
  );
}

/**
 * The invitations of the tenant (ADR-0127). An admin who is a person invites someone by name and one role, sees the
 * link once, lists the open invitations without a token, and revokes one. The menu entry follows the answer of the
 * read this page makes, as the export entry does (ADR-0115): a person without the role reads the refusal and no form.
 */
export function InvitationsView() {
  const { setCanInvite } = useApp();
  return (
    <Page title="Invitations" intro="Invite a person by name and role. They sign in through a link you send them, and their first sign-in joins them to the tenant.">
      <Queue
        title="Open invitations"
        intro="An invitation lasts seven days and is used once. This list never shows a link: only the answer to Invite does, one time."
        empty="No invitation is open."
        load={async (before, signal) => (await calls.listInvitations({ limit: QUEUE_PAGE, before }, signal)).invitations}
        head={(report) => <InviteForm report={report} />}
        onRead={(refusal) => setCanInvite(refusal === null ? true : notRefused(refusal.status))}
      >
        {(invitation, report) => <OpenInvitation invitation={invitation} report={report} />}
      </Queue>
    </Page>
  );
}
