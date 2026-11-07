import * as React from 'react';
import { cx } from './cx';
import { WORDMARK_CURSOR, WORDMARK_PATH, WORDMARK_RATIO, WORDMARK_VIEWBOX } from './brand-geometry';

export type WordmarkTone = 'default' | 'mono' | 'on-action';

export interface WordmarkProps extends Omit<React.SVGProps<SVGSVGElement>, 'height' | 'width' | 'ref'> {
  /** Height in px of the whole mark, from the dot of the i to the p's descender. Default 40, minimum 18. Width = height × 1.80. */
  height?: number;
  /** default: ink letters + cursor colour; mono: all ink; on-action: all on-action. */
  tone?: WordmarkTone;
  /** The cursor blinks. Only while something is in progress. */
  blink?: boolean;
  /** Alternative text. Default "ipso". */
  label?: string;
}

/** The ipso wordmark: Big Shoulders 600 outlines and a cursor the size of a letter. Follows the theme. */
export function Wordmark({ height = 40, tone = 'default', blink = false, label = 'ipso', className, ...rest }: WordmarkProps) {
  const h = Math.max(height, 18);
  const w = Math.round(h * WORDMARK_RATIO * 100) / 100;
  return (
    <svg
      {...rest}
      className={cx('ip-wordmark', `ip-wordmark-${tone}`, blink && 'ip-wordmark-blink', className)}
      width={w}
      height={h}
      viewBox={WORDMARK_VIEWBOX}
      role="img"
      aria-label={label}
    >
      <path className="ip-wm-t" d={WORDMARK_PATH} />
      <rect className="ip-wm-cursor" {...WORDMARK_CURSOR} />
    </svg>
  );
}
