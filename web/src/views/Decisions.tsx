import { useMemo, useState } from 'react';

import { calls } from '../api/calls';
import { usePages } from '../api/hooks';
import { TextField } from '../brand';
import { DecisionRows } from '../components/DecisionRows';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { LoadMore } from '../components/LoadMore';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { TimeControls, useTimes } from '../components/TimeControls';
import { summarize } from '../state/decision';

const PAGE = 50;

export function DecisionsView() {
  const { valid, known } = useTimes();
  const [filter, setFilter] = useState('');
  const pages = usePages(async (before, signal) => (await calls.listDecisions({ valid, known, limit: PAGE, before }, signal)).decisions, PAGE, [valid, known]);

  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (needle === '') return pages.items;
    return pages.items.filter((decision) => {
      const d = summarize(decision);
      return [d.title, d.slug, d.owner, d.criticality].some((text) => text?.toLowerCase().includes(needle));
    });
  }, [pages.items, filter]);

  return (
    <Page title="Decisions" intro="The decisions in force, each at its highest version.">
      <TimeControls valid={valid} known={known} />
      {pages.status === 'loading' ? <Loading what="decisions" /> : null}
      {pages.status === 'error' && pages.error ? <ErrorNotice error={pages.error} /> : null}
      {pages.status === 'ready' && pages.items.length === 0 ? (
        <EmptyState title="No decisions yet.">Your first receipt will appear here.</EmptyState>
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
