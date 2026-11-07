import { useMemo } from 'react';
import { Link } from 'react-router';

import { calls } from '../api/calls';
import { usePages, useResource } from '../api/hooks';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { LoadMore } from '../components/LoadMore';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { TimeControls, useTimes } from '../components/TimeControls';
import { formatTime, shortId } from '../lib/format';
import { decisionPath } from '../state/decision';
import { scopesForLabels } from './Scopes';

const PAGE = 50;
// A waiver expiring within this many days is called out, like the notice sweep (ADR-0054).
const SOON = 14;
const DAY = 24 * 60 * 60 * 1000;

/** "Expires in 3 days", in words, so a deadline never rests on a colour. */
export function expiry(expiresAt: string, now: Date): { text: string; soon: boolean } {
  const remaining = Date.parse(expiresAt) - now.getTime();
  if (Number.isNaN(remaining)) return { text: formatTime(expiresAt), soon: false };
  if (remaining <= 0) return { text: 'Expired', soon: true };
  if (remaining < DAY) return { text: 'Expires within a day', soon: true };
  const days = Math.floor(remaining / DAY);
  return { text: `Expires in ${days} ${days === 1 ? 'day' : 'days'}`, soon: days <= SOON };
}

export function WaiversView() {
  const { valid, known } = useTimes();
  const now = useMemo(() => new Date(), []);
  const pages = usePages(async (before, signal) => (await calls.listWaivers({ valid, known, limit: PAGE, before }, signal)).waivers, PAGE, [valid, known]);
  // The scope of a waiver is an id. The tree says what it stands for.
  const scopes = useResource((signal) => scopesForLabels(signal), [], { session: false });
  const selectors = useMemo(
    () => new Map(scopes.status === 'ready' ? scopes.data.map((scope) => [scope.id, `${scope.kind} ${scope.selector}`]) : []),
    [scopes],
  );

  return (
    <Page title="Waivers" intro="Time-boxed exceptions to a decision for a scope. Each one ends on its own.">
      <TimeControls valid={valid} known={known} />
      {pages.status === 'loading' ? <Loading what="waivers" /> : null}
      {pages.status === 'error' && pages.error ? <ErrorNotice error={pages.error} /> : null}
      {pages.status === 'ready' && pages.items.length === 0 ? <EmptyState title="No waiver is in force.">A waiver you record will appear here until it expires.</EmptyState> : null}
      {pages.items.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Waivers in force</caption>
            <thead>
              <tr>
                <th scope="col">Ticket</th>
                <th scope="col">Decision</th>
                <th scope="col">Scope</th>
                <th scope="col">Starts</th>
                <th scope="col">Ends</th>
              </tr>
            </thead>
            <tbody>
              {pages.items.map((waiver) => {
                const end = expiry(waiver.expires_at, now);
                return (
                  <tr key={waiver.id}>
                    <td className="mono">{waiver.ticket_ref}</td>
                    <td>
                      <Link to={decisionPath(waiver.decision_id)} className="mono">
                        {shortId(waiver.decision_id)}
                      </Link>
                    </td>
                    <td className="mono">{selectors.get(waiver.scope_id) ?? shortId(waiver.scope_id)}</td>
                    <td className="mono">{formatTime(waiver.valid_from)}</td>
                    <td>
                      <span className={end.soon ? 'deadline deadline-soon' : 'deadline'}>{end.text}</span>
                      <div className="muted mono">{formatTime(waiver.expires_at)}</div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      {pages.status === 'ready' && pages.error ? <ErrorNotice error={pages.error} /> : null}
      <LoadMore hasMore={pages.hasMore} loading={pages.loadingMore} onClick={pages.loadMore} />
    </Page>
  );
}
