import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';

import { usePages } from '../api/hooks';
import type { Report } from './Confirm';
import { ErrorNotice } from './ErrorNotice';
import { LoadMore } from './LoadMore';
import { Loading } from './Loading';
import { Notice } from './Notice';

/** How many rows a queue reads at a time. A page that holds this many may have another after it (ADR-0090). */
export const QUEUE_PAGE = 25;

/**
 * A titled list read a page at a time, with a notice above it for what a write did. A write calls `report`, which
 * shows the notice, takes the focus (the row that held the button may be gone) and reads the list again.
 */
export function Queue<T extends { id: string }>({
  title,
  intro,
  empty,
  load,
  head,
  children,
}: {
  title: string;
  intro: string;
  empty: string;
  load: (before: string | undefined, signal: AbortSignal) => Promise<T[]>;
  /** Shown above the list once the first page was read, such as the form that adds a row. It reports like a row does. */
  head?: (report: (report: Report) => void) => ReactNode;
  children: (item: T, report: (report: Report) => void) => ReactNode;
}) {
  const pages = usePages(load, QUEUE_PAGE, []);
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
      {pages.status === 'ready' && head ? head(report) : null}
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
