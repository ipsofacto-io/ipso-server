import { useEffect, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';

import { calls } from '../api/calls';
import { usePages } from '../api/hooks';
import type { AdvisoryVerdict } from '../api/types';
import { Button, TextField } from '../brand';
import { AdvisoryVerdictsList } from '../components/AdvisoryVerdictsList';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { LoadMore } from '../components/LoadMore';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { SelectField } from '../components/SelectField';

const PAGE = 50;

type AssessmentFilter = '' | AdvisoryVerdict['assessment'];

function parseAssessment(raw: string | null): AssessmentFilter {
  if (raw === 'deviates' || raw === 'complies' || raw === 'unclear') return raw;
  return '';
}

function parsePullNumber(raw: string | null): number | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!/^[1-9][0-9]*$/.test(trimmed)) return undefined;
  const n = Number(trimmed);
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

export function AdvisoryView() {
  const [params, setParams] = useSearchParams();
  const activeRepo = params.get('repo')?.trim() ?? '';
  const activePullRaw = params.get('pull_number')?.trim() ?? '';
  const activePull = parsePullNumber(activePullRaw);
  const activeAssessment = parseAssessment(params.get('assessment'));

  const [repoInput, setRepoInput] = useState(activeRepo);
  const [pullInput, setPullInput] = useState(activePullRaw);
  const [assessmentInput, setAssessmentInput] = useState<AssessmentFilter>(activeAssessment);
  const [pullError, setPullError] = useState<string | undefined>(undefined);

  useEffect(() => {
    setRepoInput(activeRepo);
    setPullInput(activePullRaw);
    setAssessmentInput(activeAssessment);
    setPullError(undefined);
  }, [activeRepo, activePullRaw, activeAssessment]);

  const pages = usePages(
    async (before, signal) =>
      (
        await calls.listAdvisoryVerdicts(
          {
            ...(activeRepo ? { repo: activeRepo } : {}),
            ...(activePull !== undefined ? { pull_number: activePull } : {}),
            ...(activeAssessment ? { assessment: activeAssessment } : {}),
            limit: PAGE,
            before,
          },
          signal,
        )
      ).advisory_verdicts,
    PAGE,
    [activeRepo, activePull, activeAssessment],
  );

  function applyFilters(event: FormEvent) {
    event.preventDefault();
    const trimmedPull = pullInput.trim();
    if (trimmedPull !== '' && parsePullNumber(trimmedPull) === undefined) {
      setPullError('Enter a positive pull request number.');
      return;
    }
    setPullError(undefined);
    const next = new URLSearchParams();
    const trimmedRepo = repoInput.trim();
    if (trimmedRepo) next.set('repo', trimmedRepo);
    if (trimmedPull) next.set('pull_number', trimmedPull);
    if (assessmentInput) next.set('assessment', assessmentInput);
    setParams(next);
  }

  function clearFilters() {
    setRepoInput('');
    setPullInput('');
    setAssessmentInput('');
    setPullError(undefined);
    setParams(new URLSearchParams());
  }

  const hasFilters = activeRepo !== '' || activePull !== undefined || activeAssessment !== '';

  return (
    <Page
      title="Advisory verdicts"
      intro="AI-generated pull request feedback from llm-advisory checks. These verdicts are advisory only and never block a merge or count toward compliance."
    >
      <form className="form-row" onSubmit={applyFilters} role="search" aria-label="Filter advisory verdicts" noValidate>
        <TextField
          label="Repository"
          mono
          placeholder="owner/name"
          value={repoInput}
          onChange={(event) => setRepoInput(event.target.value)}
        />
        <TextField
          label="Pull request"
          mono
          inputMode="numeric"
          placeholder="42"
          value={pullInput}
          error={pullError}
          onChange={(event) => setPullInput(event.target.value)}
        />
        <SelectField
          label="Assessment"
          value={assessmentInput}
          onChange={(event) => setAssessmentInput(parseAssessment(event.target.value))}
        >
          <option value="">All assessments</option>
          <option value="deviates">Deviates</option>
          <option value="complies">Complies</option>
          <option value="unclear">Unclear</option>
        </SelectField>
        <div className="form-actions">
          <Button type="submit" variant="secondary" size="sm">
            Filter
          </Button>
          {hasFilters ? (
            <Button type="button" variant="quiet" size="sm" onClick={clearFilters}>
              Clear
            </Button>
          ) : null}
        </div>
      </form>

      {pages.status === 'loading' ? <Loading what="advisory verdicts" /> : null}
      {pages.status === 'error' && pages.error ? <ErrorNotice error={pages.error} onRetry={pages.reload} /> : null}
      {pages.status === 'ready' && pages.items.length === 0 ? (
        <EmptyState title="No advisory verdicts match.">
          {hasFilters ? 'Adjust or clear the filters to see other advisory verdicts.' : 'Advisory verdicts appear here once opted-in repositories evaluate llm-advisory checks on open pull requests.'}
        </EmptyState>
      ) : null}
      {pages.items.length > 0 ? <AdvisoryVerdictsList verdicts={pages.items} showDecision headingLevel={2} /> : null}
      <LoadMore hasMore={pages.hasMore} loading={pages.loadingMore} onClick={pages.loadMore} />
    </Page>
  );
}
