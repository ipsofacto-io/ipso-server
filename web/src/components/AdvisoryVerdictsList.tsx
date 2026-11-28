import { Link } from 'react-router';

import type { AdvisoryPlace, AdvisoryVerdict } from '../api/types';
import { Status, type StatusTone } from '../brand';
import { formatTime } from '../lib/format';
import { decisionPath } from '../state/decision';
import { ModelLabel } from './ModelLabel';
import { ExternalLink } from './Safe';

export const ADVISORY_VERDICT_NOTICE = 'AI-generated advisory verdict. Does not block a merge or count toward compliance.';

const ASSESSMENT_STATUS: Record<AdvisoryVerdict['assessment'], { tone: StatusTone; label: string }> = {
  deviates: { tone: 'needs-review', label: 'Deviates (advisory)' },
  complies: { tone: 'verified', label: 'Complies (advisory)' },
  unclear: { tone: 'verifying', label: 'Unclear (advisory)' },
};

function formatPlace(place: AdvisoryPlace): string {
  return place.start_line === place.end_line ? `${place.path}:${place.start_line}` : `${place.path}:${place.start_line}-${place.end_line}`;
}

/**
 * Renders stored llm-advisory verdicts as plain text with the AI-generated label, model_id,
 * prompt_version, and non-blocking notice on every row (ADR-0152, ADR-0174, IPSO-162).
 * Model reasons are always rendered as React text nodes, never Markdown or HTML, and no author
 * or person field is shown.
 */
export function AdvisoryVerdictsList({
  verdicts,
  showDecision = true,
  headingLevel = 2,
}: {
  verdicts: AdvisoryVerdict[];
  showDecision?: boolean;
  headingLevel?: 2 | 3 | 4;
}) {
  const Heading = headingLevel === 2 ? 'h2' : headingLevel === 3 ? 'h3' : 'h4';
  return (
    <ul className="plain stack" aria-label="Advisory verdicts">
      {verdicts.map((verdict) => {
        const badge = ASSESSMENT_STATUS[verdict.assessment] ?? { tone: 'verifying' as const, label: `${verdict.assessment} (advisory)` };
        const headingText = verdict.decision_title || verdict.decision_id;
        return (
          <li key={verdict.id}>
            <article className="card">
              <header className="card-head">
                <Heading className="card-title">
                  {showDecision ? <Link to={decisionPath(verdict.decision_id)}>{headingText}</Link> : `Check #${verdict.check_index}`}
                </Heading>
                <Status tone={badge.tone}>{badge.label}</Status>
              </header>
              <p>{verdict.reason}</p>
              {verdict.cited.length > 0 ? (
                <section aria-label="Cited lines">
                  <ul className="plain">
                    {verdict.cited.map((place, index) => (
                      <li key={`${place.path}:${place.start_line}:${place.end_line}:${index}`} className="mono">
                        {formatPlace(place)}
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}
              <dl className="meta">
                <div>
                  <dt>Pull request</dt>
                  <dd>
                    <ExternalLink href={verdict.pull_url}>{`${verdict.repo}#${verdict.pull_number}`}</ExternalLink>
                  </dd>
                </div>
                <div>
                  <dt>Commit</dt>
                  <dd className="mono">{verdict.head_sha.slice(0, 7)}</dd>
                </div>
                <div>
                  <dt>Decision version</dt>
                  <dd className="mono">{`v${verdict.decision_version}, check #${verdict.check_index}`}</dd>
                </div>
                <ModelLabel modelID={verdict.model_id} promptVersion={verdict.prompt_version} />
                <div>
                  <dt>Recorded</dt>
                  <dd className="mono">{formatTime(verdict.recorded_at)}</dd>
                </div>
              </dl>
              <p className="muted">{ADVISORY_VERDICT_NOTICE}</p>
            </article>
          </li>
        );
      })}
    </ul>
  );
}
