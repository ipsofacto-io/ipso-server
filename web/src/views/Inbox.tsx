import { Link } from 'react-router';

import { calls } from '../api/calls';
import type { AgentProposal, CheckProposal, Proposal } from '../api/types';
import { Code } from '../brand';
import type { Report } from '../components/Confirm';
import { DecisionStatus } from '../components/DecisionStatus';
import { Page } from '../components/Page';
import { Queue, QUEUE_PAGE } from '../components/Queue';
import { ExternalLink } from '../components/Safe';
import { formatTime, shortId } from '../lib/format';
import { asString, asStrings, preview } from '../lib/json';
import { decisionPath } from '../state/decision';
import { proposalTitle } from '../state/draft';
import { CheckActions, ReviewActions } from './ReviewActions';

const RAW_LIMIT = 8_000;

const advisory = 'A person approves it, and it does not block a merge.';

function ModelLabel({ modelID, promptVersion }: { modelID: string; promptVersion: string }) {
  return (
    <div>
      <dt>AI-generated</dt>
      <dd className="mono">{`${modelID}, prompt ${promptVersion}`}</dd>
    </div>
  );
}

function Advisory() {
  return <p className="muted">{advisory}</p>;
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
        <ModelLabel modelID={proposal.model_id} promptVersion={proposal.prompt_version} />
        <div>
          <dt>Captured</dt>
          <dd className="mono">{formatTime(proposal.captured_at)}</dd>
        </div>
      </dl>
      <Advisory />
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

// A template check names a built-in template of ipso and holds no rule of its own (ADR-0165).
function TemplateCheck({ proposal, ref, name, report }: { proposal: CheckProposal; ref: string; name: string; report: (report: Report) => void }) {
  const reads = [...asStrings(proposal.spec.resources), ...asStrings(proposal.spec.languages)];
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{`Check for ${name}`}</h3>
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
          <dt>Template</dt>
          <dd>{asString(proposal.spec.title) ?? ref}</dd>
        </div>
        <div>
          <dt>Ref</dt>
          <dd className="mono">{ref}</dd>
        </div>
        <div>
          <dt>Reads</dt>
          <dd className="mono">{reads.length > 0 ? reads.join(', ') : '-'}</dd>
        </div>
        <ModelLabel modelID={proposal.model_id} promptVersion={proposal.prompt_version} />
        <div>
          <dt>Captured</dt>
          <dd className="mono">{formatTime(proposal.captured_at)}</dd>
        </div>
      </dl>
      <Advisory />
      <p className="muted">The model chose this built-in template of ipso. The rule and its tests ship with the ipso version that builds the check.</p>
      <CheckActions decisionId={proposal.decision_id} id={proposal.id} title={`the check for ${name}, captured ${formatTime(proposal.captured_at)}`} report={report} />
    </>
  );
}

function DraftedCheck({ proposal, report }: { proposal: CheckProposal; report: (report: Report) => void }) {
  const name = `decision ${shortId(proposal.decision_id)}, version ${proposal.decision_version}`;
  if (proposal.ref) return <TemplateCheck proposal={proposal} ref={proposal.ref} name={name} report={report} />;
  const fixtures = proposal.fixtures.length;
  const source = proposal.rego ?? '';
  const rego = source.length > RAW_LIMIT ? `${source.slice(0, RAW_LIMIT)}\n# ... cut` : source;
  return (
    <>
      <header className="card-head">
        <h3 className="card-title">{`Check for ${name}`}</h3>
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
          <dd className="mono">{`${proposal.engine}, ${proposal.target ?? '-'}`}</dd>
        </div>
        <div>
          <dt>Fixtures</dt>
          <dd className="mono">{fixtures} passed</dd>
        </div>
        <div>
          <dt>Repaired</dt>
          <dd>{proposal.repaired ? 'Once, after a first failure' : 'No'}</dd>
        </div>
        <ModelLabel modelID={proposal.model_id} promptVersion={proposal.prompt_version} />
        <div>
          <dt>Captured</dt>
          <dd className="mono">{formatTime(proposal.captured_at)}</dd>
        </div>
      </dl>
      <Advisory />
      <details>
        <summary>Policy</summary>
        <Code lang="rego">{rego}</Code>
      </details>
      <CheckActions decisionId={proposal.decision_id} id={proposal.id} title={`the check for ${name}, captured ${formatTime(proposal.captured_at)}`} report={report} />
    </>
  );
}

export function InboxView() {
  return (
    <Page
      title="Inbox"
      intro="Drafts that wait for a person. Approve a draft to record it as a decision, or reject it. Approving a drafted check records the answer only: it writes no decision, and an approved check reaches a repository only when someone runs ipso deliver there."
    >
      <Queue
        title="Pull requests"
        intro="Decisions a model found in merged pull requests."
        empty="No pull request waits for review."
        load={async (before, signal) => (await calls.listProposals({ limit: QUEUE_PAGE, before }, signal)).proposals}
      >
        {(proposal, report) => <PullRequest proposal={proposal} report={report} />}
      </Queue>
      <Queue
        title="Coding agents"
        intro="Decisions your coding agents proposed."
        empty="No agent has proposed a decision."
        load={async (before, signal) => (await calls.listAgentProposals({ limit: QUEUE_PAGE, before }, signal)).agent_proposals}
      >
        {(proposal, report) => <FromAgent proposal={proposal} report={report} />}
      </Queue>
      <Queue
        title="Drafted checks"
        intro="Checks drafted for a decision that passed every fixture. A check is answered once, and a rejected rule is not drafted again for the same version of the decision."
        empty="No drafted check waits for review."
        load={async (before, signal) => (await calls.listCheckProposals({ limit: QUEUE_PAGE, before }, signal)).check_proposals}
      >
        {(proposal, report) => <DraftedCheck proposal={proposal} report={report} />}
      </Queue>
    </Page>
  );
}
