import { useCallback, useEffect, useRef, useState, type DependencyList } from 'react';

import { useApp } from '../app/AppContext';
import { ApiError, toApiError } from './client';

export type Resource<T> =
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'error'; error: ApiError };

/**
 * Loads one answer. It loads again when `deps` change, cancels the request it replaces, and tells the app
 * whether a call was answered (signed in) or refused with 401 (signed out). A call that says nothing about
 * the session, such as the list of providers, passes `session: false`.
 */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList,
  { session = true }: { session?: boolean } = {},
): Resource<T> & { reload(): void } {
  const app = useApp();
  const [state, setState] = useState<Resource<T>>({ status: 'loading' });
  const [attempt, setAttempt] = useState(0);
  const { begin, setSignedIn } = app;

  useEffect(() => {
    const controller = new AbortController();
    const end = begin();
    setState({ status: 'loading' });
    load(controller.signal)
      .then(
        (data) => {
          if (controller.signal.aborted) return;
          if (session) setSignedIn(true);
          setState({ status: 'ready', data });
        },
        (error: unknown) => {
          if (controller.signal.aborted) return;
          const refusal = toApiError(error);
          if (session && refusal.status === 401) setSignedIn(false);
          setState({ status: 'error', error: refusal });
        },
      )
      .finally(end);
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, attempt, begin, setSignedIn]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);
  return { ...state, reload };
}

export interface Pages<T> {
  items: T[];
  status: 'loading' | 'ready' | 'error';
  /** The error of the first page, or of the page after it. */
  error: ApiError | null;
  hasMore: boolean;
  loadingMore: boolean;
  loadMore(): void;
}

/**
 * Loads a list a page at a time, from the highest id (ADR-0090). A page that holds `pageSize` items may
 * have another after it. `load` returns one page, newest first.
 */
export function usePages<T extends { id: string }>(
  load: (before: string | undefined, signal: AbortSignal) => Promise<T[]>,
  pageSize: number,
  deps: DependencyList,
): Pages<T> {
  const { begin, setSignedIn } = useApp();
  const [items, setItems] = useState<T[]>([]);
  const [status, setStatus] = useState<Pages<T>['status']>('loading');
  const [error, setError] = useState<ApiError | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const generation = useRef(0);
  const inFlight = useRef(new Set<AbortController>());
  const loadRef = useRef(load);
  loadRef.current = load;
  const itemsRef = useRef<T[]>([]);
  itemsRef.current = items;

  const fetchPage = useCallback(
    async (before: string | undefined, first: boolean) => {
      const mine = generation.current;
      const controller = new AbortController();
      inFlight.current.add(controller);
      const end = begin();
      try {
        const page = await loadRef.current(before, controller.signal);
        if (mine !== generation.current) return;
        setSignedIn(true);
        setItems((current) => (first ? page : [...current, ...page]));
        setHasMore(page.length >= pageSize);
        setError(null);
        setStatus('ready');
      } catch (cause) {
        if (mine !== generation.current) return;
        const refusal = toApiError(cause);
        if (refusal.status === 401) setSignedIn(false);
        setError(refusal);
        if (first) setStatus('error');
      } finally {
        inFlight.current.delete(controller);
        end();
        if (mine === generation.current) setLoadingMore(false);
      }
    },
    [begin, setSignedIn, pageSize],
  );

  useEffect(() => {
    generation.current += 1;
    setItems([]);
    setHasMore(false);
    setError(null);
    setStatus('loading');
    setLoadingMore(false);
    void fetchPage(undefined, true);
    const running = inFlight.current;
    return () => {
      generation.current += 1;
      for (const controller of running) controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, fetchPage]);

  const loadMore = useCallback(() => {
    const last = itemsRef.current.at(-1);
    if (!last) return;
    setLoadingMore(true);
    void fetchPage(last.id, false);
  }, [fetchPage]);

  return { items, status, error, hasMore, loadingMore, loadMore };
}
