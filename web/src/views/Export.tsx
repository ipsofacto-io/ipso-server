import { useEffect, useState, type FormEvent } from 'react';

import { calls, exportArchivePath } from '../api/calls';
import { toApiError, type ApiError } from '../api/client';
import { useWrite } from '../api/hooks';
import type { Export } from '../api/types';
import { useApp } from '../app/AppContext';
import { Button, Code, TextField } from '../brand';
import { ErrorNotice } from '../components/ErrorNotice';
import { Loading } from '../components/Loading';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { formatBytes, formatTime } from '../lib/format';
import { canDownload, checkRecipient, exportNotRefused, isUnderWay } from '../state/export';

const TITLE = 'Export';
const POLL_MS = 5000;
/** The longest delay a timer takes: 2^31 - 1 milliseconds. */
const MAX_TIMEOUT = 2 ** 31 - 1;
const CONFLICT = 'An export is already under way. It is shown above once the page has read it again.';
const INVALID = 'The server could not read the key. Give one age public key, which starts with age1, on one line.';

const STATE_TEXT: Record<Export['state'], string> = {
  pending: 'Waiting for the worker',
  running: 'Being made',
  ready: 'Ready to download',
  failed: 'Failed',
};

type Held = { status: 'loading' } | { status: 'ready'; export: Export | null } | { status: 'error'; error: ApiError };

/**
 * Reads the export the tenant holds, and again every few seconds while it is being made, keeping the last answer
 * on screen. A 404 is an answer: there is none. A 403 is the refusal of the role policy and is shown as it is.
 */
function useCurrentExport() {
  const { begin, setSignedIn, setCanExport } = useApp();
  const [held, setHeld] = useState<Held>({ status: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const end = begin();
    calls
      .currentExport(controller.signal)
      .then(
        (current) => {
          if (controller.signal.aborted) return;
          setSignedIn(true);
          setCanExport(true);
          setHeld({ status: 'ready', export: current });
        },
        (cause: unknown) => {
          if (controller.signal.aborted) return;
          const error = toApiError(cause);
          setCanExport(exportNotRefused(error.status));
          if (error.status === 404) {
            setSignedIn(true);
            setHeld({ status: 'ready', export: null });
            return;
          }
          if (error.status === 401) setSignedIn(false);
          // A read that fails in the middle of a wait keeps what the page already shows.
          setHeld((last) => (last.status === 'ready' && error.status !== 401 && error.status !== 403 ? last : { status: 'error', error }));
        },
      )
      .finally(end);
    return () => controller.abort();
  }, [attempt, begin, setSignedIn, setCanExport]);

  const underWay = held.status === 'ready' && isUnderWay(held.export);
  useEffect(() => {
    if (!underWay) return;
    const timer = setInterval(() => setAttempt((n) => n + 1), POLL_MS);
    return () => clearInterval(timer);
  }, [underWay]);

  // A ready export is not read again, so the page reads it when it expires: the link goes and the form comes back.
  const expiresAt = held.status === 'ready' && held.export?.state === 'ready' ? held.export.expires_at : null;
  useEffect(() => {
    const wait = expiresAt === null ? 0 : Date.parse(expiresAt) - Date.now();
    if (!(wait > 0)) return;
    const timer = setTimeout(() => setAttempt((n) => n + 1), Math.min(wait + 1000, MAX_TIMEOUT));
    return () => clearTimeout(timer);
  }, [expiresAt]);

  return {
    held,
    reload: () => setAttempt((n) => n + 1),
    show: (current: Export) => setHeld({ status: 'ready', export: current }),
  };
}

function Facts({ held }: { held: Export }) {
  const ready = held.state === 'ready';
  return (
    <dl className="meta">
      <div>
        <dt>Asked</dt>
        <dd>{formatTime(held.created_at)}</dd>
      </div>
      {held.finished_at ? (
        <div>
          <dt>Finished</dt>
          <dd>{formatTime(held.finished_at)}</dd>
        </div>
      ) : null}
      <div>
        <dt>Expires</dt>
        <dd>{formatTime(held.expires_at)}</dd>
      </div>
      {ready && held.bytes !== null ? (
        <div>
          <dt>Size</dt>
          <dd>{formatBytes(held.bytes)}</dd>
        </div>
      ) : null}
      {ready && held.sha256 ? (
        <div>
          <dt>SHA-256</dt>
          <dd className="mono">{held.sha256}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function Archive({ held }: { held: Export }) {
  const file = `ipso-export-${held.id}.age`;
  return (
    <>
      {/* The attachment header makes the browser save the body as it arrives, so this page never holds the archive. A refusal is a page of JSON in the new tab and never a file named .age, which a download attribute could make. */}
      <div className="actions">
        <a className="ip-btn ip-btn-primary" href={exportArchivePath(held.id)} target="_blank" rel="noopener noreferrer">
          Download the archive
        </a>
      </div>
      <p className="muted">If the new tab shows an error instead of saving a file, wait a minute and try again: the server sends two archives at once.</p>
      <Code title="Open it with stock tools" lang="sh">{`age --decrypt -i key.txt ${file} | gunzip | jq -c .`}</Code>
    </>
  );
}

function ExportCard({ held }: { held: Export }) {
  return (
    <section className="card" aria-labelledby="export-state">
      <div className="card-head">
        <h2 id="export-state" className="card-title">
          {STATE_TEXT[held.state]}
        </h2>
      </div>
      <Facts held={held} />
      {held.state === 'pending' || held.state === 'running' ? (
        <p className="muted">The worker finds a request within a minute. This page reads the export again every few seconds.</p>
      ) : null}
      {held.state === 'failed' ? <p className="muted">The export could not be made. The log of the worker says why. You can ask again.</p> : null}
      {canDownload(held, Date.now()) ? <Archive held={held} /> : null}
    </section>
  );
}

function AskForm({ replaces, onAsked }: { replaces: boolean; onAsked: (current: Export | 'again') => void }) {
  const write = useWrite((recipient: string) => calls.startExport({ recipient }));
  const [value, setValue] = useState('');
  const [tried, setTried] = useState(false);
  const [secret, setSecret] = useState(false);
  const check = checkRecipient(value);
  const error = secret ? 'That is a private key. Never paste it here: paste the public key, which starts with age1.' : tried && !check.ok ? check.error : undefined;
  const sending = write.status === 'sending';

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (!check.ok) {
      // A private key is never sent, and it does not stay in the field either.
      if (check.privateKey) {
        setSecret(true);
        setValue('');
      }
      return;
    }
    const outcome = await write.run(check.recipient);
    if (outcome.status === 'done') {
      setValue('');
      setTried(false);
      onAsked(outcome.result);
    } else if (outcome.status === 'failed' && outcome.error.status === 409) {
      onAsked('again');
    }
  }

  return (
    <>
      <form className="form" onSubmit={submit} noValidate>
        <fieldset className="fieldset" disabled={sending}>
          <legend className="ip-label">{replaces ? 'Ask for a new export' : 'Ask for an export'}</legend>
          <TextField
            label="Age public key"
            mono
            autoComplete="off"
            spellCheck={false}
            value={value}
            error={error}
            hint="Starts with age1. The archive is encrypted to this key and to nobody else. Keep the private key: ipso never sees it."
            onChange={(event) => {
              setSecret(false);
              setValue(event.target.value);
            }}
          />
          {replaces ? <p className="muted">A new export replaces this one. You can ask again ten minutes after the last one finished.</p> : null}
        </fieldset>
        <div className="actions">
          <Button type="submit" variant="primary" disabled={sending}>
            {sending ? 'Asking' : 'Ask for the export'}
          </Button>
        </div>
      </form>
      {write.status === 'failed' && write.error.status === 429 ? (
        <Notice tone="error" title="You asked for an export a short while ago.">
          <p>{write.error.retryAfter ? `Ask again in ${Math.ceil(write.error.retryAfter / 60)} minutes.` : 'Ask again in a few minutes.'}</p>
        </Notice>
      ) : write.status === 'failed' ? (
        <ErrorNotice error={write.error} conflict={CONFLICT} invalid={INVALID} />
      ) : null}
    </>
  );
}

/**
 * The export of the tenant (ADR-0111, ADR-0115). An admin who is a person asks for it with one age public key,
 * reads its state until it is ready, and downloads it. The page holds a public key and an export id, never the
 * archive and never a private key. A person without the role reads the refusal and nothing else.
 */
export function ExportView() {
  const { held, reload, show } = useCurrentExport();

  return (
    <Page title={TITLE} intro="The whole tenant in one archive, encrypted to a key you give. It is kept for 24 hours. Restore and offboarding stay operator commands.">
      {held.status === 'loading' ? <Loading what="the export" /> : null}
      {held.status === 'error' ? <ErrorNotice error={held.error} onRetry={reload} /> : null}
      {held.status === 'ready' ? (
        <>
          {held.export ? <ExportCard held={held.export} /> : null}
          {isUnderWay(held.export) ? null : (
            <AskForm
              key={held.export?.id ?? 'none'}
              replaces={held.export?.state === 'ready'}
              onAsked={(current) => (current === 'again' ? reload() : show(current))}
            />
          )}
        </>
      ) : null}
    </Page>
  );
}
