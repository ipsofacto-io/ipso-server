import * as React from 'react';
import { cx } from './cx';

export interface CodeProps {
  title?: string;
  lang?: string;
  /** Blinking cursor at the end, for content still arriving. */
  caret?: boolean;
  children: string;
  className?: string;
}

/** Code block with an optional title bar and a live cursor. */
export function Code({ title, lang, caret, children, className }: CodeProps) {
  return (
    <figure className={cx('ip-code', className)}>
      {(title || lang) && (
        <figcaption className="ip-code-head">
          <span>{title ?? ''}</span>
          {lang ? <span>{lang}</span> : null}
        </figcaption>
      )}
      <pre>
        <code>{children}</code>
        {caret ? <span className="ip-code-caret" aria-hidden="true" /> : null}
      </pre>
    </figure>
  );
}
