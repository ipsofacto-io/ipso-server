import * as React from 'react';
import { cx } from './cx';

export type StatusTone = 'verified' | 'verifying' | 'needs-review' | 'rejected';

export interface StatusProps {
  tone: StatusTone;
  /** Replaces the default label. */
  children?: React.ReactNode;
  className?: string;
}

const LABEL: Record<StatusTone, string> = {
  verified: 'Verified',
  verifying: 'Verifying',
  'needs-review': 'Needs review',
  rejected: 'Rejected',
};

function Icon({ tone }: { tone: StatusTone }) {
  switch (tone) {
    case 'verified':
      return (
        <>
          <circle className="ip-i-a" cx={8} cy={8} r={7} />
          <path className="ip-i-b" d="M4.6 8.2 L7 10.4 L11.4 5.8" />
        </>
      );
    case 'verifying':
      return <circle className="ip-i-a" cx={8} cy={8} r={6.2} />;
    case 'needs-review':
      return (
        <>
          <circle className="ip-i-a" cx={8} cy={8} r={6.2} />
          <path className="ip-i-b" d="M5.5 8 H10.5" />
        </>
      );
    case 'rejected':
      return (
        <>
          <circle className="ip-i-a" cx={8} cy={8} r={7} />
          <path className="ip-i-b" d="M5.6 5.6 L10.4 10.4 M10.4 5.6 L5.6 10.4" />
        </>
      );
  }
}

/** The status of a decision, always with a word and an icon. */
export function Status({ tone, children, className }: StatusProps) {
  return (
    <span className={cx('ip-status', `ip-status-${tone}`, className)}>
      <svg width={16} height={16} viewBox="0 0 16 16" aria-hidden="true">
        <Icon tone={tone} />
      </svg>
      {children ?? LABEL[tone]}
    </span>
  );
}
