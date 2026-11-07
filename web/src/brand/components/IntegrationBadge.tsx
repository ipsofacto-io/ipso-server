import * as React from 'react';
import { cx } from './cx';
import { Mascot } from './Mascot';
import { Wordmark } from './Wordmark';

export interface IntegrationBadgeProps {
  /** Link to the public receipt. When set, the badge is a link. */
  href?: string;
  /** Default "Verifiable decision with". */
  kicker?: string;
  className?: string;
}

/** The badge shown next to an outcome produced with ipso. Don't recolour it. */
export function IntegrationBadge({ href, kicker = 'Verifiable decision with', className }: IntegrationBadgeProps) {
  const inner = (
    <>
      <span className="ip-ibadge-face" aria-hidden="true">
        <Mascot size={15} tone="action" label="" />
      </span>
      <span className="ip-ibadge-text">
        <span className="ip-ibadge-kicker">{kicker}</span>
        <Wordmark height={25} tone="on-action" />
      </span>
    </>
  );
  return href ? (
    <a className={cx('ip-ibadge', className)} href={href}>
      {inner}
    </a>
  ) : (
    <span className={cx('ip-ibadge', className)}>{inner}</span>
  );
}
