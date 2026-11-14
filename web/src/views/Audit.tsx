import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';

import { calls } from '../api/calls';
import { useResource } from '../api/hooks';
import type { AuditBeliefs, AuditChain, AuditWaivers, Decision, StoredVerdict } from '../api/types';
import { Button, TextField } from '../brand';
import { DecisionRows } from '../components/DecisionRows';
import { DecisionStatus } from '../components/DecisionStatus';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { Loading } from '../components/Loading';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { ExternalLink } from '../components/Safe';
import { VerdictReading } from '../components/VerdictReading';
import { fieldToTime, formatTime, nowForField, shortId, timeToField } from '../lib/format';
import { decisionPath, summarize } from '../state/decision';

type Values = Readonly<Record<string, string>>;

interface Field {
  name: string;
  label: string;
  kind: 'text' | 'time';
  required?: boolean;
  hint?: string;
  /** A value that does not match is refused before the question is asked, with patternError. */
  pattern?: RegExp;
  patternError?: string;
}

const REPO: Field = { name: 'repo', label: 'Repository', kind: 'text', required: true, hint: 'A lowercase owner/name.' };
const PATH: Field = { name: 'path', label: 'Path', kind: 'text', hint: 'Relative to the repository root. Without one, the answer is wider.' };
const ENV: Field = { name: 'env', label: 'Environment', kind: 'text', hint: 'Without one, the answer is wider.' };

// A commit as an upload names it, 40 or 64 hexadecimal digits (ADR-0124).
const COMMIT: Field = {
  name: 'sha',
  label: 'Commit',
  kind: 'text',
  required: true,
  hint: 'The merge commit, 40 or 64 hexadecimal digits.',
  pattern: /^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/,
  patternError: 'A commit is 40 or 64 hexadecimal digits.',
};

/** What is wrong with the value of a field, or nothing. */
function problem(f: Field, value: string): string | undefined {
  const text = value.trim();
  if (f.required && text === '') return 'Required.';
  if (f.pattern && text !== '' && !f.pattern.test(text)) return f.patternError ?? 'Not a valid value.';
  return undefined;
}

const field = (values: Values, name: string): string => values[name] ?? '';
const optional = (values: Values, name: string): string | undefined => values[name] || undefined;

/**
 * One question of the audit (section 2.3). The fields live in the address, so an answer can be shared and
 * asked again, and a question asks only when every required field is there. The times are read as UTC.
 */
function Question<T>({
  title,
  intro,
  fields,
  run,
  tooWide,
  children,
}: {
  title: string;
  intro: string;
  fields: Field[];
  run: (values: Values, signal: AbortSignal) => Promise<T>;
  /** What to say when the answer is over the cap, when a path and an environment do not narrow it. */
  tooWide?: string;
  children: (data: T) => ReactNode;
}) {
  const [params, setParams] = useSearchParams();
  const fromAddress = () =>
    Object.fromEntries(
      fields.map((f) => {
        const given = params.get(f.name);
        if (f.kind === 'time') return [f.name, given ? timeToField(given) : f.required ? nowForField() : ''];
        return [f.name, given ?? ''];
      }),
    );
  const [form, setForm] = useState<Record<string, string>>(fromAddress);
  const [tried, setTried] = useState(false);
  const address = params.toString();

  // The address is the truth: back, forward and a shared link change it without a click on Ask.
  useEffect(() => {
    setForm(fromAddress());
    setTried(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address]);

  const asked = useMemo(() => Object.fromEntries(fields.flatMap((f) => (params.get(f.name) ? [[f.name, params.get(f.name) as string]] : []))), [fields, params]);
  const ready = fields.every((f) => !f.required || asked[f.name]);

  function ask(event: FormEvent) {
    event.preventDefault();
    setTried(true);
    if (fields.some((f) => problem(f, form[f.name] ?? ''))) return;
    const next = new URLSearchParams();
    for (const f of fields) {
      const value = (form[f.name] ?? '').trim();
      if (value !== '') next.set(f.name, f.kind === 'time' ? fieldToTime(value) : value);
    }
    setParams(next);
  }

  return (
    <Page title={title} intro={intro} actions={<Link to="/audit">All questions</Link>}>
      <form className="form-row" onSubmit={ask} noValidate>
        {fields.map((f) => {
          const refused = tried ? problem(f, form[f.name] ?? '') : undefined;
          return (
            <TextField
              key={f.name}
              label={`${f.label}${f.kind === 'time' ? ' (UTC)' : ''}`}
              type={f.kind === 'time' ? 'datetime-local' : 'text'}
              mono
              required={f.required}
              value={form[f.name] ?? ''}
              onChange={(event) => setForm((current) => ({ ...current, [f.name]: event.target.value }))}
              {...(refused ? { error: refused } : f.hint ? { hint: f.hint } : {})}
            />
          );
        })}
        <div className="form-actions">
          <Button type="submit" variant="primary">
            Ask
          </Button>
        </div>
      </form>
      {ready ? <Answer key={params.toString()} asked={asked} run={run} tooWide={tooWide} render={children} /> : null}
    </Page>
  );
}

function Answer<T>({
  asked,
  run,
  tooWide,
  render,
}: {
  asked: Values;
  run: (values: Values, signal: AbortSignal) => Promise<T>;
  tooWide?: string;
  render: (data: T) => ReactNode;
}) {
  const answer = useResource((signal) => run(asked, signal), []);
  return (
    <section className="answer" aria-label="Answer" aria-live="polite">
      {answer.status === 'loading' ? <Loading what="the answer" /> : null}
      {answer.status === 'error' ? <ErrorNotice error={answer.error} onRetry={answer.reload} tooWide={tooWide} /> : null}
      {answer.status === 'ready' ? render(answer.data) : null}
    </section>
  );
}

const QUESTIONS = [
  { to: '/audit/decisions', name: 'What applied', text: 'The decisions that applied to a repository, a path and an environment at a time, as the registry knew them at another.' },
  { to: '/audit/beliefs', name: 'What changed', text: 'How the registry\'s belief about a subject changed between two times.' },
  { to: '/audit/merges', name: 'At a merge', text: 'The decisions that applied when a change merged.' },
  { to: '/audit/supersessions', name: 'Supersessions', text: 'The chain of decisions that replaced one another.' },
  { to: '/audit/waivers', name: 'Waivers ending soon', text: 'The waivers that end within 14 days.' },
] as const;

export function AuditIndexView() {
  return (
    <Page title="Audit" intro="Five questions the registry answers for an auditor. Every answer is for a time and for what the registry knew then.">
      <ul className="cards cards-grid">
        {QUESTIONS.map((question) => (
          <li key={question.to} className="card">
            <h2 className="card-title">
              <Link to={question.to}>{question.name}</Link>
            </h2>
            <p className="muted">{question.text}</p>
          </li>
        ))}
      </ul>
    </Page>
  );
}

function Decisions({ decisions, caption }: { decisions: Decision[]; caption: string }) {
  if (decisions.length === 0) return <EmptyState title="No decision applied." />;
  return <DecisionRows decisions={decisions} caption={caption} />;
}

export function AuditDecisionsView() {
  return (
    <Question
      title="What applied"
      intro="The decisions that applied to a subject at a valid time, as known at a transaction time."
      fields={[REPO, PATH, ENV, { name: 'valid', label: 'In force at', kind: 'time', required: true }, { name: 'known', label: 'Known at', kind: 'time', required: true }]}
      run={(v, signal) =>
        calls.auditDecisions({ repo: field(v, 'repo'), path: optional(v, 'path'), env: optional(v, 'env'), valid: field(v, 'valid'), known: field(v, 'known') }, signal)
      }
    >
      {(data) => <Decisions decisions={data.decisions} caption="Decisions that applied" />}
    </Question>
  );
}

export function AuditBeliefsView() {
  return (
    <Question
      title="What changed"
      intro="How what the registry believed for a subject changed between two times."
      fields={[
        REPO,
        PATH,
        ENV,
        { name: 'valid', label: 'In force at', kind: 'time', required: true },
        { name: 'then', label: 'Known then', kind: 'time', required: true },
        { name: 'now', label: 'Known now', kind: 'time', required: true },
      ]}
      run={(v, signal) =>
        calls.auditBeliefs(
          { repo: field(v, 'repo'), path: optional(v, 'path'), env: optional(v, 'env'), valid: field(v, 'valid'), then: field(v, 'then'), now: field(v, 'now') },
          signal,
        )
      }
    >
      {(data) => <Beliefs data={data} />}
    </Question>
  );
}

function Beliefs({ data }: { data: AuditBeliefs }) {
  if (data.added.length === 0 && data.removed.length === 0 && data.changed.length === 0) {
    return <EmptyState title="Nothing changed between these times." />;
  }
  return (
    <>
      <h2 className="queue-title">Added</h2>
      {data.added.length === 0 ? <p className="muted">No decision was added.</p> : <DecisionRows decisions={data.added} caption="Decisions added" />}
      <h2 className="queue-title">Removed</h2>
      {data.removed.length === 0 ? <p className="muted">No decision was removed.</p> : <DecisionRows decisions={data.removed} caption="Decisions removed" />}
      <h2 className="queue-title">Changed</h2>
      {data.changed.length === 0 ? (
        <p className="muted">No decision changed.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Decisions that changed</caption>
            <thead>
              <tr>
                <th scope="col">Decision</th>
                <th scope="col">Then</th>
                <th scope="col">Now</th>
              </tr>
            </thead>
            <tbody>
              {data.changed.map((change) => {
                const then = summarize(change.then);
                const now = summarize(change.now);
                return (
                  <tr key={change.id}>
                    <td>
                      <Link to={decisionPath(change.id)}>{now.title}</Link>
                    </td>
                    <td>
                      <DecisionStatus status={then.status} /> <span className="muted mono">version {then.version}</span>
                    </td>
                    <td>
                      <DecisionStatus status={now.status} /> <span className="muted mono">version {now.version}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function AuditMergesView() {
  return (
    <Question
      title="At a merge"
      intro="The decisions that applied when a change merged, and what the CI runs on its commit said about them. The merge time is also the time the registry knew them, unless you give another."
      fields={[
        REPO,
        COMMIT,
        PATH,
        ENV,
        { name: 'at', label: 'Merged at', kind: 'time', required: true },
        { name: 'known', label: 'Known at', kind: 'time', hint: 'Runs stored after this time are not in the answer. Give a later time to include the runs that finished after the merge.' },
      ]}
      tooWide="This commit has more verdicts than one answer holds. A path and an environment narrow only the decisions, not the verdicts."
      run={(v, signal) =>
        calls.auditMerges(
          { repo: field(v, 'repo'), sha: field(v, 'sha'), path: optional(v, 'path'), env: optional(v, 'env'), at: field(v, 'at'), known: optional(v, 'known') },
          signal,
        )
      }
    >
      {(data) => (
        <>
          <Decisions decisions={data.decisions} caption="Decisions at the merge" />
          <MergeVerdicts verdicts={data.verdicts} />
        </>
      )}
    </Question>
  );
}

/**
 * The verdicts that CI runs stored for the commit. A commit that no stored run names is unknown, which is not the same as
 * clean, so it gets a notice and no table (ADR-0124). Each verdict is read as on the decision page, and path and
 * environment narrow only the decisions, so every environment of the commit is shown.
 */
function MergeVerdicts({ verdicts }: { verdicts: StoredVerdict[] | null }) {
  return (
    <section aria-label="Verdicts from CI">
      <h2 className="queue-title">Verdicts from CI on this commit</h2>
      {verdicts === null ? (
        <Notice title="Unknown, not clean">
          No CI run on this commit had been stored by the time asked about. Nothing passed and nothing failed. A run that finished after the merge needs a later
          Known at.
        </Notice>
      ) : verdicts.length === 0 ? (
        <p className="muted">The runs on this commit reported no decision check.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Verdicts of the runs on the commit</caption>
            <thead>
              <tr>
                <th scope="col">Decision</th>
                <th scope="col">Result</th>
                <th scope="col">Mode</th>
                <th scope="col">Violations</th>
                <th scope="col">Check</th>
                <th scope="col">Environment</th>
                <th scope="col">Run</th>
                <th scope="col">Evaluated</th>
              </tr>
            </thead>
            <tbody>
              {verdicts.map((verdict) => (
                <tr key={verdict.id}>
                  <td>
                    <Link to={decisionPath(verdict.slug)}>{verdict.slug}</Link>
                  </td>
                  <td>
                    <VerdictReading verdict={verdict} />
                  </td>
                  <td>{verdict.mode}</td>
                  <td className="mono">{verdict.violations}</td>
                  <td>{verdict.check}</td>
                  <td className="mono">{verdict.env === '' ? 'none' : verdict.env}</td>
                  <td>
                    <ExternalLink href={verdict.run_url}>{`${verdict.run_id}.${verdict.run_attempt}`}</ExternalLink>
                  </td>
                  <td className="mono">{formatTime(verdict.evaluated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function AuditSupersessionsView() {
  return (
    <Question
      title="Supersessions"
      intro="The chain of decisions that replaced one another, and the versions of each."
      fields={[
        { name: 'decision', label: 'Decision id', kind: 'text', required: true, hint: 'The registry id of any decision in the chain.' },
        { name: 'known', label: 'Known at', kind: 'time', required: true },
      ]}
      run={(v, signal) => calls.auditSupersessions(field(v, 'decision'), { known: field(v, 'known') }, signal)}
    >
      {(data) => <Chain chain={data} />}
    </Question>
  );
}

function Chain({ chain }: { chain: AuditChain }) {
  if (chain.links.length === 0 && chain.versions.length === 0) return <EmptyState title="This decision has no supersession chain." />;
  return (
    <>
      <h2 className="queue-title">Links</h2>
      {chain.links.length === 0 ? (
        <p className="muted">Nothing supersedes this decision, and it supersedes nothing.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Supersession links</caption>
            <thead>
              <tr>
                <th scope="col">Replaced</th>
                <th scope="col">By</th>
                <th scope="col">From</th>
              </tr>
            </thead>
            <tbody>
              {chain.links.map((link) => (
                <tr key={link.id}>
                  <td>
                    <Link to={decisionPath(link.from)} className="mono">
                      {shortId(link.from)}
                    </Link>
                  </td>
                  <td>
                    <Link to={decisionPath(link.to)} className="mono">
                      {shortId(link.to)}
                    </Link>
                  </td>
                  <td className="mono">{formatTime(link.effective_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h2 className="queue-title">Versions</h2>
      <div className="table-wrap">
        <table className="table">
          <caption className="sr-only">Versions of the decisions in the chain</caption>
          <thead>
            <tr>
              <th scope="col">Decision</th>
              <th scope="col">Version</th>
              <th scope="col">Valid from</th>
              <th scope="col">Valid to</th>
            </tr>
          </thead>
          <tbody>
            {chain.versions.map((version) => (
              <tr key={`${version.decision_id}@${version.version}`}>
                <td>
                  <Link to={decisionPath(version.decision_id)} className="mono">
                    {shortId(version.decision_id)}
                  </Link>
                </td>
                <td className="mono">{version.version}</td>
                <td className="mono">{formatTime(version.valid_from)}</td>
                <td className="mono">{version.valid_to ? formatTime(version.valid_to) : 'open'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function AuditWaiversView() {
  return (
    <Question
      title="Waivers ending soon"
      intro="The waivers that end within 14 days of a clock, the soonest first."
      fields={[
        { name: 'known', label: 'Known at', kind: 'time', required: true },
        { name: 'now', label: 'Clock', kind: 'time', required: true, hint: 'The time the 14 days start from.' },
      ]}
      run={(v, signal) => calls.auditWaivers({ known: field(v, 'known'), now: field(v, 'now') }, signal)}
    >
      {(data) => <EndingWaivers data={data} />}
    </Question>
  );
}

function EndingWaivers({ data }: { data: AuditWaivers }) {
  if (data.waivers.length === 0) return <EmptyState title="No waiver ends within 14 days." />;
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Waivers ending soon</caption>
        <thead>
          <tr>
            <th scope="col">Ticket</th>
            <th scope="col">Decision</th>
            <th scope="col">Scope</th>
            <th scope="col">Ends</th>
          </tr>
        </thead>
        <tbody>
          {data.waivers.map((waiver) => (
            <tr key={waiver.id}>
              <td className="mono">{waiver.ticket_ref}</td>
              <td>
                <Link to={decisionPath(waiver.decision_id)} className="mono">
                  {shortId(waiver.decision_id)}
                </Link>
              </td>
              <td className="mono">{shortId(waiver.scope_id)}</td>
              <td className="mono">{formatTime(waiver.expires_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
