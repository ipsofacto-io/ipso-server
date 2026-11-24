import { useMemo, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';

import { calls } from '../api/calls';
import { usePages } from '../api/hooks';
import { Button, TextField } from '../brand';
import { DecisionRows } from '../components/DecisionRows';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { LinkButton } from '../components/LinkButton';
import { LoadMore } from '../components/LoadMore';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { TimeControls, useTimes } from '../components/TimeControls';
import { summarize } from '../state/decision';

const PAGE = 50;

export function DecisionsView() {
  const { valid, known } = useTimes();
  const [params, setParams] = useSearchParams();
  const activeQuery = params.get('q')?.trim() ?? '';
  const [queryInput, setQueryInput] = useState(activeQuery);
  const [filter, setFilter] = useState('');

  const pages = usePages(
    async (before, signal) =>
      (
        await calls.listDecisions(
          {
            ...(activeQuery ? { q: activeQuery } : {}),
            valid,
            known,
            limit: PAGE,
            before,
          },
          signal,
        )
      ).decisions,
    PAGE,
    [activeQuery, valid, known],
  );

  function submitSearch(event: FormEvent) {
    event.preventDefault();
    const next = new URLSearchParams(params);
    const trimmed = queryInput.trim();
    if (trimmed) {
      next.set('q', trimmed);
    } else {
      next.delete('q');
    }
    setParams(next);
  }

  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (needle === '') return pages.items;
    return pages.items.filter((decision) => {
      const d = summarize(decision);
      return [d.title, d.slug, d.owner, d.criticality].some((text) => text?.toLowerCase().includes(needle));
    });
  }, [pages.items, filter]);

  return (
    <Page
      title="Decisions"
      intro="The decisions in force, each at its highest version."
      actions={
        <LinkButton to="/decisions/new" size="sm">
          New decision
        </LinkButton>
      }
    >
      <TimeControls valid={valid} known={known} />
      <form className="form-row" onSubmit={submitSearch} role="search" aria-label="Full-text search">
        <TextField
          label="Search registry"
          type="search"
          value={queryInput}
          onChange={(event) => setQueryInput(event.target.value)}
          hint="Full-text search across decision titles, slugs, statements, and tags."
        />
        <div className="actions">
          <Button type="submit" variant="secondary" size="sm">
            Search
          </Button>
          {activeQuery ? (
            <Button
              type="button"
              variant="quiet"
              size="sm"
              onClick={() => {
                setQueryInput('');
                const next = new URLSearchParams(params);
                next.delete('q');
                setParams(next);
              }}
            >
              Clear search
            </Button>
          ) : null}
        </div>
      </form>
      {pages.status === 'loading' ? <Loading what="decisions" /> : null}
      {pages.status === 'error' && pages.error ? <ErrorNotice error={pages.error} /> : null}
      {pages.status === 'ready' && pages.items.length === 0 ? (
        activeQuery ? (
          <EmptyState title="No decisions match this search.">Try a broader topic or clear the full-text search.</EmptyState>
        ) : (
          <EmptyState title="No decisions yet.">Your first receipt will appear here.</EmptyState>
        )
      ) : null}
      {pages.status === 'ready' && pages.items.length > 0 ? (
        <>
          <TextField
            label="Filter"
            type="search"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            hint="Matches the title, slug, owner and criticality of the decisions loaded."
          />
          {shown.length === 0 ? <p className="muted">No loaded decision matches this filter.</p> : <DecisionRows decisions={shown} caption="Decisions in force" />}
          {pages.error ? <ErrorNotice error={pages.error} /> : null}
          <LoadMore hasMore={pages.hasMore} loading={pages.loadingMore} onClick={pages.loadMore} />
        </>
      ) : null}
    </Page>
  );
}
