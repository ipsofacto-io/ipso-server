import type { ReactNode } from 'react';

import { Mascot } from '../brand';

/** Ipso is idle here: nothing is being checked, and the mascot says no status of its own. */
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <Mascot state="idle" size={56} label="" />
      <p className="empty-title">{title}</p>
      {children ? <div className="empty-body">{children}</div> : null}
    </div>
  );
}
