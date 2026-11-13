import { useEffect, useRef, type ReactNode } from 'react';

import { useWrite } from '../api/hooks';
import { Button } from '../brand';
import { ErrorNotice } from './ErrorNotice';
import { useFocusOnMount } from './useFocusOnMount';

/** What a queue says above its cards after a write, and the reason it reads the queue again. */
export interface Report {
  tone: 'info' | 'error';
  title: string;
  body?: ReactNode;
}

/**
 * One confirmation and one request, for an answer that cannot be undone: a draft, a drafted check or a premise
 * review reason. A 409 or a 404 means that it was answered or removed under the person, so the queue reads again.
 * Any other refusal stays here, in words. The group takes the focus, because the button that opened it is gone.
 */
export function Confirm({
  label,
  question,
  button,
  busy,
  variant,
  send,
  success,
  stale,
  report,
  onCancel,
}: {
  label: string;
  question: string;
  button: string;
  busy: string;
  variant: 'primary' | 'danger';
  send(): Promise<unknown>;
  success: Report;
  /** What the queue says when the answer was a 404 or a 409: someone answered first. */
  stale: Report;
  report(report: Report): void;
  onCancel(): void;
}) {
  const write = useWrite(send);
  const group = useFocusOnMount<HTMLDivElement>();

  async function answer() {
    const outcome = await write.run();
    if (outcome.status === 'done') report(success);
    else if (outcome.status === 'failed' && (outcome.error.status === 409 || outcome.error.status === 404)) report(stale);
  }

  return (
    <div ref={group} tabIndex={-1} className="review" role="group" aria-label={label}>
      <p>{question}</p>
      {write.status === 'failed' ? <ErrorNotice error={write.error} /> : null}
      <div className="actions">
        <Button variant={variant} size="sm" onClick={answer} disabled={write.status === 'sending'}>
          {write.status === 'sending' ? busy : button}
        </Button>
        <Button variant="quiet" size="sm" onClick={onCancel} disabled={write.status === 'sending'}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

/** Where the focus goes after a Cancel: the confirmation that held it is gone, so it returns to the buttons. */
export function useActionsFocus(idle: boolean) {
  const actions = useRef<HTMLDivElement>(null);
  const cancelled = useRef(false);
  useEffect(() => {
    if (idle && cancelled.current) {
      cancelled.current = false;
      actions.current?.querySelector('button')?.focus();
    }
  }, [idle]);
  return {
    actions,
    cancel: () => {
      cancelled.current = true;
    },
  };
}
