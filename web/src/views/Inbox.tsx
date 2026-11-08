import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router';

import { calls } from '../api/calls';
import { usePages } from '../api/hooks';
import type { AgentProposal, CheckProposal, Proposal } from '../api/types';
import { Code } from '../brand';
import { DecisionStatus } from '../components/DecisionStatus';
import { ErrorNotice } from '../components/ErrorNotice';
import { LoadMore } from '../components/LoadMore';
import { Loading } from '../components/Loading';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { ExternalLink } from '../components/Safe';
import { formatTime, shortId } from '../lib/format';
import { preview } from '../lib/json';
import { decisionPath } from '../state/decision';
import { proposalTitle } from '../state/draft';
import { ReviewActions, type Report } from './ReviewActions';

const PAGE = 25;
const RAW_LIMIT = 8_000;

function Queue<T extends { id: string }>({
  title,
  intro,
  empty,
  load,
  children,
}: {
  title: string;
  intro: string;
  empty: string;
  load: (before: string | undefined, signal: AbortSignal) => Promise<T[]>;
  children: (item: T, report: (report: Report) => void) => ReactNode;
}) {
  const pages = usePages(load, PAGE, []);
  const { reload } = pages;
  const [notice, setNotice] = useState<Report | null>(null);
  const noticeRef = useRef<HTMLDivElement>(null);
  // A write says what happened above the cards and reads the queue again: the card that was answered is gone
  // from the new page, and its button with it, so the focus moves to the notice.
  const report = useCallback(
    (next: Report) => {
      setNotice(next);
      reload();
    },
    [reload],
  );
  useEffect(() => {
    if (notice) noticeRef.current?.focus();
  }, [notice]);
  const headingId = `queue-${title.toLowerCase().replace(/[^a-z]+/g, '-')}`;
  return (
    <section className="queue" aria-labelledby={headingId}>
      <h2 id={headingId} className="queue-title">
        {title}
      </h2>
      <p className="muted">{intro}</p>
      {notice ? (
        <div ref={noticeRef} tabIndex={-1} className="queue-notice">
          <Notice tone={notice.tone} title={notice.title}>
            {notice.body}
          </Notice>
        </div>
      ) : null}
      {pages.status === 'loading' ? <Loading what={title.toLowerCase()} /> : null}
      {pages.status === 'error' && pages.error ? <ErrorNotice error={pages.error} /> : null}
      {pages.status === 'ready' && pages.items.length === 0 ? <p className="queue-empty">{empty}</p> : null}
      {pages.items.length > 0 ? (
        <ul className="cards">
          {pages.items.map((item) => (
            <li key={item.id} className="card">
              {children(item, report)}
            </li>
          ))}
        </ul>
      ) : null}
      {pages.status === 'ready' && pages.error ? <ErrorNotice error={pages.error} /> : null}
      <LoadMore hasMore={pages.hasMore} loading={pages.loadingMore} onClick={pages.loadMore} />
    </section>
  );
}

function Raw({ value, title }: { value: unknown; title: string }) {
  return (
    <details>
      <summary>{title}</summary>
      <Code lang="json">{preview(value, RAW_LIMIT)}</Code>
    </details>
  );
}

function PullRequest({ proposal, report }: { proposal: Proposal; report: (report: Report) => void }) {
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{proposalTitle(proposal.payload)}</h3>
        <DecisionStatus status="proposed" />
      </header>
      <dl className="meta">
        <div>
          <dt>Pull request</dt>
          <dd>
            <ExternalLink href={proposal.source_url}>{`${proposal.repo}#${proposal.pr_number}`}</ExternalLink>
          </dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd className="mono">{Math.round(proposal.confidence * 100)}%</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd className="mono">{`${proposal.model_id}, prompt ${proposal.prompt_version}`}</dd>
        </div>
        <div>
          <dt>Captured</dt>
          <dd className="mono">{formatTime(proposal.captured_at)}</dd>
        </div>
      </dl>
      <p className="muted">A model drafted this from the merged pull request. It is untrusted until a person approves it.</p>
      <Raw value={proposal.payload} title="Draft" />
      <ReviewActions queue="proposals" id={proposal.id} payload={proposal.payload} sourceUrl={proposal.source_url} report={report} />
    </>
  );
}

function FromAgent({ proposal, report }: { proposal: AgentProposal; report: (report: Report) => void }) {
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{proposalTitle(proposal.payload)}</h3>
        <DecisionStatus status="proposed" />
      </header>
      <dl className="meta">
        <div>
          <dt>Proposed by</dt>
          <dd>A coding agent</dd>
        </div>
        <div>
          <dt>Captured</dt>
          <dd className="mono">{formatTime(proposal.captured_at)}</dd>
        </div>
      </dl>
      <Raw value={proposal.payload} title="Draft" />
      <ReviewActions queue="agent-proposals" id={proposal.id} payload={proposal.payload} report={report} />
    </>
  );
}

function DraftedCheck({ proposal }: { proposal: CheckProposal }) {
  const fixtures = proposal.fixtures.length;
  const rego = proposal.rego.length > RAW_LIMIT ? `${proposal.rego.slice(0, RAW_LIMIT)}\n# ... cut` : proposal.rego;
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{`Check for decision ${shortId(proposal.decision_id)}, version ${proposal.decision_version}`}</h3>
        <DecisionStatus status="proposed" />
      </header>
      <dl className="meta">
        <div>
          <dt>Decision</dt>
          <dd>
            <Link to={decisionPath(proposal.decision_id)}>Open the decision</Link>
          </dd>
        </div>
        <div>
          <dt>Engine</dt>
          <dd className="mono">{`${proposal.engine}, ${proposal.target}`}</dd>
        </div>
        <div>
          <dt>Fixtures</dt>
          <dd className="mono">{fixtures} passed</dd>
        </div>
        <div>
          <dt>Repaired</dt>
          <dd>{proposal.repaired ? 'Once, after a first failure' : 'No'}</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd className="mono">{`${proposal.model_id}, prompt ${proposal.prompt_version}`}</dd>
        </div>
        <div>
          <dt>Captured</dt>
          <dd className="mono">{formatTime(proposal.captured_at)}</dd>
        </div>
      </dl>
      <details>
        <summary>Policy</summary>
        <Code lang="rego">{rego}</Code>
      </details>
    </>
  );
}

export function InboxView() {
  return (
    <Page
      title="Inbox"
      intro="Drafts that wait for a person. Approve a draft to record it as a decision, or reject it. A drafted check cannot be approved here yet: approve it in its pull request."
    >
      <Queue
        title="Pull requests"
        intro="Decisions a model found in merged pull requests."
        empty="No pull request waits for review."
        load={async (before, signal) => (await calls.listProposals({ limit: PAGE, before }, signal)).proposals}
      >
        {(proposal, report) => <PullRequest proposal={proposal} report={report} />}
      </Queue>
      <Queue
        title="Coding agents"
        intro="Decisions your coding agents proposed."
        empty="No agent has proposed a decision."
        load={async (before, signal) => (await calls.listAgentProposals({ limit: PAGE, before }, signal)).agent_proposals}
      >
        {(proposal, report) => <FromAgent proposal={proposal} report={report} />}
      </Queue>
      <Queue
        title="Drafted checks"
        intro="Checks drafted for a decision that passed every fixture."
        empty="No drafted check waits for review."
        load={async (before, signal) => (await calls.listCheckProposals({ limit: PAGE, before }, signal)).check_proposals}
      >
        {(proposal) => <DraftedCheck proposal={proposal} />}
      </Queue>
    </Page>
  );
}
