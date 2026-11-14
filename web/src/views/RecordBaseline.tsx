import { useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';

import { calls } from '../api/calls';
import { useResource, useWrite } from '../api/hooks';
import type { BaselineRequest } from '../api/types';
import { Button, TextField } from '../brand';
import { DecisionPicker, loadAllDecisions } from '../components/DecisionPicker';
import { ErrorNotice } from '../components/ErrorNotice';
import { LinkButton } from '../components/LinkButton';
import { Loading } from '../components/Loading';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { useFocusOnMount } from '../components/useFocusOnMount';
import { shortId } from '../lib/format';
import { baselineRequest, checkBaseline, checkFileSize, plain, readExport, TOO_LARGE, type BaselineErrors, type BaselineExport } from '../state/baseline';
import { decisionPath, summarize } from '../state/decision';

const TITLE = 'Record a baseline';
const CONFLICT =
  'The decision needs its grandfather terms first, which the supersession page records. A decision has one baseline for a repository, and a recorded baseline cannot be changed.';

/** The file the person chose: being read, refused with the reason, or read and ready to send. */
type Picked = { name: string; status: 'reading' } | { name: string; status: 'refused'; error: string } | { name: string; status: 'ready'; file: BaselineExport };

/**
 * Records the fingerprints of one repository for a decision that has grandfather terms (ADR-0121). The file is the
 * export of `ipso baseline export`, which holds digests and no salt, and the page checks it before it sends: the
 * decision it was made for, the digests, and the size of the request. A baseline is recorded once, so the page says
 * so above the button and a double click sends one request.
 */
export function RecordBaselineView() {
  const [params] = useSearchParams();
  const decisions = useResource((signal) => loadAllDecisions(signal), []);
  const write = useWrite((decision: string, request: BaselineRequest) => calls.recordBaseline(decision, request));
  const [decisionId, setDecisionId] = useState(params.get('decision') ?? '');
  const [repo, setRepo] = useState('');
  const [picked, setPicked] = useState<Picked | null>(null);
  const [tried, setTried] = useState(false);
  // A later choice of file wins over a read that is still running.
  const reads = useRef(0);
  const done = useFocusOnMount<HTMLDivElement>();

  const all = decisions.status === 'ready' ? decisions.data : [];
  const chosen = all.find((decision) => decision.id === decisionId);
  const summary = chosen ? summarize(chosen) : null;
  const edrId = summary?.edrId ?? null;
  const file = picked?.status === 'ready' ? picked.file : null;
  const errors = checkBaseline({ decisionId, edrId, repo, file });
  // A file that was chosen is checked at once: the person has already acted on it.
  const fileProblem = picked?.status === 'refused' ? picked.error : picked?.status === 'ready' ? errors.file : undefined;
  const shown: BaselineErrors = { ...(tried ? errors : {}), ...(fileProblem ? { file: fileProblem } : {}) };
  // A file that is still being read is neither missing nor refused yet.
  if (picked?.status === 'reading') delete shown.file;
  const sending = write.status === 'sending';

  async function choose(event: ChangeEvent<HTMLInputElement>) {
    const next = event.target.files?.[0];
    const read = (reads.current += 1);
    if (!next) {
      setPicked(null);
      return;
    }
    const tooBig = checkFileSize(next.size);
    if (tooBig) {
      setPicked({ name: plain(next.name), status: 'refused', error: tooBig });
      return;
    }
    setPicked({ name: plain(next.name), status: 'reading' });
    let text: string;
    try {
      text = await next.text();
    } catch {
      if (read === reads.current) setPicked({ name: plain(next.name), status: 'refused', error: 'The file could not be read.' });
      return;
    }
    if (read !== reads.current) return;
    const result = readExport(text);
    setPicked(result.ok ? { name: plain(next.name), status: 'ready', file: result.value } : { name: plain(next.name), status: 'refused', error: result.error });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (Object.keys(errors).length > 0 || !file) return;
    await write.run(decisionId, baselineRequest(repo, file.fingerprints));
  }

  function again() {
    setRepo('');
    setPicked(null);
    setTried(false);
    write.reset();
  }

  if (write.status === 'done') {
    const { fingerprint_count: count, repo: recorded } = write.result;
    return (
      <Page title={TITLE}>
        <div ref={done} tabIndex={-1}>
          <Notice title="Baseline recorded.">
            <p>
              {count.toLocaleString('en-US')} fingerprints are recorded for {recorded} under {summary?.title ?? `decision ${shortId(decisionId)}`}.
            </p>
            <p>The grandfather terms of the decision say how long the baseline counts. It cannot be changed from the app.</p>
          </Notice>
        </div>
        <div className="actions">
          <LinkButton to={decisionPath(decisionId)} variant="primary">
            Open the decision
          </LinkButton>
          <Button onClick={again}>Record another repository</Button>
        </div>
      </Page>
    );
  }

  return (
    <Page title={TITLE} intro="Record the fingerprints of the violations that already exist in one repository, so the grandfather terms of a decision have a baseline to apply.">
      {decisions.status === 'loading' ? <Loading what="decisions" /> : null}
      {decisions.status === 'error' ? <ErrorNotice error={decisions.error} onRetry={decisions.reload} /> : null}
      {decisions.status === 'ready' ? (
        <form className="form" onSubmit={submit} noValidate>
          <fieldset className="fieldset" disabled={sending}>
            <legend className="ip-label">The baseline</legend>
            <DecisionPicker
              label="Decision"
              hint="It needs its grandfather terms first."
              decisions={decisions.data}
              value={decisionId}
              error={shown.decisionId}
              onChange={setDecisionId}
            />
            <TextField
              label="Repository"
              mono
              value={repo}
              error={shown.repo}
              hint="A lowercase owner/name, such as acme/payments. A baseline holds one repository."
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setRepo(event.target.value)}
            />
            <TextField
              label="Baseline file"
              type="file"
              accept=".json,application/json"
              error={shown.file}
              hint={
                picked?.status === 'ready'
                  ? `${picked.name} holds ${picked.file.fingerprints.length.toLocaleString('en-US')} fingerprints.`
                  : 'The file that ipso baseline export wrote, at most 8 MiB.'
              }
              onChange={choose}
            />
            <p className="muted">
              In the checkout of the repository, run <code>ipso baseline export {edrId ?? '<EDR id of the decision>'} &gt; baseline-export.json</code> and choose that file. It holds fingerprints and no salt, and nothing else leaves the checkout.
            </p>
          </fieldset>

          {write.status === 'failed' ? (
            <ErrorNotice error={write.error} conflict={CONFLICT} invalid="Check the repository name and the file." tooLarge={TOO_LARGE} />
          ) : null}

          <p>
            <strong>A baseline is recorded once.</strong> A decision has one baseline for a repository, and the app cannot change or remove it. Check the repository and the file first.
          </p>
          <div className="actions">
            <Button type="submit" variant="primary" disabled={sending}>
              {sending ? 'Recording' : 'Record the baseline'}
            </Button>
            <LinkButton to={decisionId === '' ? '/decisions' : decisionPath(decisionId)} variant="quiet">
              Cancel
            </LinkButton>
          </div>
        </form>
      ) : null}
    </Page>
  );
}
