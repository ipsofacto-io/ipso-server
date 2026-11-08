import { Link, useParams } from 'react-router';

import { calls } from '../api/calls';
import { useResource } from '../api/hooks';
import type { Decision } from '../api/types';
import { DecisionStatus } from '../components/DecisionStatus';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { LinkButton } from '../components/LinkButton';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { ExternalLink } from '../components/Safe';
import { TimeControls, useTimes } from '../components/TimeControls';
import { formatDate, formatTime, nowAsTime } from '../lib/format';
import { checkLines, decisionPath, premiseLines, scopeLines, sourceLines, summarize, supersedes } from '../state/decision';

export function DecisionDetailView() {
  const { ref = '' } = useParams();
  const { valid, known } = useTimes();
  const decisions = useResource((signal) => calls.getDecision(ref, { valid, known }, signal), [ref, valid, known]);

  return (
    <Page title="Decision" actions={<Link to="/decisions">All decisions</Link>}>
      <TimeControls valid={valid} known={known} />
      {decisions.status === 'loading' ? <Loading what="the decision" /> : null}
      {decisions.status === 'error' ? <ErrorNotice error={decisions.error} onRetry={decisions.reload} /> : null}
      {decisions.status === 'ready' && decisions.data.decisions.length === 0 ? (
        <EmptyState title="No decision matches this reference.">It may not exist, or it may not have been in force at that time.</EmptyState>
      ) : null}
      {decisions.status === 'ready'
        ? decisions.data.decisions.map((decision) => <DecisionCard key={`${decision.id}@${decision.version}`} decision={decision} />)
        : null}
    </Page>
  );
}

function DecisionCard({ decision }: { decision: Decision }) {
  const d = summarize(decision);
  const scopes = scopeLines(decision);
  const checks = checkLines(decision);
  const premises = premiseLines(decision);
  const sources = sourceLines(decision);
  const replaced = supersedes(decision);
  return (
    <article className="card" aria-labelledby={`decision-${d.id}`}>
      <header className="card-head">
        <h2 id={`decision-${d.id}`} className="card-title">
          {d.title}
        </h2>
        <DecisionStatus status={d.status} />
      </header>
      {d.status === 'superseded' || d.status === 'deprecated' ? <Successor id={d.id} /> : null}
      <dl className="meta">
        <div>
          <dt>Registry id</dt>
          <dd className="mono">{d.id}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd className="mono">{d.version}</dd>
        </div>
        {d.slug ? (
          <div>
            <dt>Slug</dt>
            <dd className="mono">{d.slug}</dd>
          </div>
        ) : null}
        <div>
          <dt>Owner</dt>
          <dd className="mono">{d.owner ?? 'none'}</dd>
        </div>
        <div>
          <dt>Criticality</dt>
          <dd>{d.criticality ?? 'none'}</dd>
        </div>
        <div>
          <dt>Valid from</dt>
          <dd className="mono">{d.validFrom ? formatDate(d.validFrom) : 'none'}</dd>
        </div>
        <div>
          <dt>Valid to</dt>
          <dd className="mono">{d.validTo ? formatDate(d.validTo) : 'open'}</dd>
        </div>
        <div>
          <dt>Review by</dt>
          <dd className="mono">{d.reviewBy ? formatDate(d.reviewBy) : 'none'}</dd>
        </div>
        {replaced.length > 0 ? (
          <div>
            <dt>Supersedes</dt>
            <dd className="mono">{replaced.join(', ')}</dd>
          </div>
        ) : null}
        {d.tags.length > 0 ? (
          <div>
            <dt>Tags</dt>
            <dd className="mono">{d.tags.join(', ')}</dd>
          </div>
        ) : null}
      </dl>

      {scopes.length > 0 ? (
        <section aria-label="Scope">
          <h3 className="ip-label">Scope</h3>
          <ul className="plain">
            {scopes.map((line) => (
              <li key={line} className="mono">
                {line}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {checks.length > 0 ? (
        <section aria-label="Checks">
          <h3 className="ip-label">Checks</h3>
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">Checks of this decision</caption>
              <thead>
                <tr>
                  <th scope="col">Engine</th>
                  <th scope="col">Reference</th>
                  <th scope="col">Mode</th>
                </tr>
              </thead>
              <tbody>
                {checks.map((check, index) => (
                  <tr key={`${check.engine}-${index}`}>
                    <td className="mono">{check.engine}</td>
                    <td className="mono">{check.target ?? 'none'}</td>
                    <td>{check.mode ?? 'block'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {premises.length > 0 ? (
        <section aria-label="Premises">
          <h3 className="ip-label">Premises</h3>
          <ul className="plain">
            {premises.map((premise) => (
              <li key={premise.id}>
                {premise.statement}
                <span className="muted mono">
                  {' '}
                  {premise.id}
                  {premise.every ? `, checked every ${premise.every} days` : ''}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {sources.length > 0 ? (
        <section aria-label="Sources">
          <h3 className="ip-label">Sources</h3>
          <ul className="plain">
            {sources.map((source) => (
              <li key={source.url}>
                {source.type}: <ExternalLink href={source.url}>{source.url}</ExternalLink>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {d.edrId ?? d.slug ? <Verdicts decision={(d.edrId ?? d.slug) as string} /> : null}
      <p>
        <Link to={`/audit/supersessions?decision=${encodeURIComponent(d.id)}&known=${encodeURIComponent(nowAsTime())}`}>
          Supersession chain of this decision
        </Link>
      </p>
      <div className="actions">
        <LinkButton to={`/waivers/new?decision=${encodeURIComponent(d.id)}`} size="sm">
          Record a waiver
        </LinkButton>
        <LinkButton to={`/supersessions/new?from=${encodeURIComponent(d.id)}`} size="sm">
          Supersede this decision
        </LinkButton>
      </div>
    </article>
  );
}

/** A superseded or deprecated decision names its successor, which only the supersession chain knows (Q4). */
function Successor({ id }: { id: string }) {
  const chain = useResource((signal) => calls.auditSupersessions(id, { known: nowAsTime() }, signal), [id]);
  if (chain.status !== 'ready') return null;
  const link = chain.data.links.find((candidate) => candidate.from === id);
  if (!link) return null;
  return (
    <p className="successor">
      Replaced by <Link to={decisionPath(link.to)}>this decision</Link> from {formatTime(link.effective_at)}.
    </p>
  );
}

const SHOWN = 20;

function Verdicts({ decision }: { decision: string }) {
  const verdicts = useResource((signal) => calls.listVerdicts({ decision, limit: SHOWN }, signal), [decision]);
  return (
    <section aria-label="Verdicts">
      <h3 className="ip-label">Verdicts from CI</h3>
      {verdicts.status === 'loading' ? <Loading what="verdicts" /> : null}
      {verdicts.status === 'error' && verdicts.error.status !== 401 ? <ErrorNotice error={verdicts.error} onRetry={verdicts.reload} /> : null}
      {verdicts.status === 'ready' && verdicts.data.verdicts.length === 0 ? (
        <p className="muted">No CI run has reported on this decision yet.</p>
      ) : null}
      {verdicts.status === 'ready' && verdicts.data.verdicts.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Verdicts uploaded by CI runs</caption>
            <thead>
              <tr>
                <th scope="col">Result</th>
                <th scope="col">Mode</th>
                <th scope="col">Violations</th>
                <th scope="col">Repository</th>
                <th scope="col">Run</th>
                <th scope="col">Evaluated</th>
              </tr>
            </thead>
            <tbody>
              {verdicts.data.verdicts.map((verdict) => (
                <tr key={verdict.id}>
                  <td>
                    <span className={verdict.result === 'fail' || verdict.result === 'error' ? 'result result-bad' : 'result'}>{verdict.result}</span>
                  </td>
                  <td>{verdict.mode}</td>
                  <td className="mono">{verdict.violations}</td>
                  <td className="mono">{verdict.repo}</td>
                  <td>
                    <ExternalLink href={verdict.run_url}>{`${verdict.run_id}.${verdict.run_attempt}`}</ExternalLink>
                  </td>
                  <td className="mono">{formatTime(verdict.evaluated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {verdicts.status === 'ready' && verdicts.data.verdicts.length === SHOWN ? <p className="muted">Showing the newest {SHOWN} verdicts.</p> : null}
    </section>
  );
}
