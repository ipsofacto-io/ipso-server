import * as React from 'react';
import { cx } from './cx';
import { Button } from './Button';
import { Status, type StatusTone } from './Status';
import { Wordmark } from './Wordmark';

export interface DecisionReceiptProps {
  id?: string;
  question: string;
  premises: string[];
  status?: StatusTone;
  outcome?: string;
  fingerprint?: string;
  signature?: string;
  /** Agent · date and time. */
  meta?: string;
  onVerify?: () => void;
  verifyHref?: string;
  /** Default "Verify decision". */
  verifyLabel?: string;
  className?: string;
}

/** The receipt of a decision: question, premises, conclusion, fingerprint and signature. Never put Ipso inside. */
export function DecisionReceipt({
  id,
  question,
  premises,
  status = 'verified',
  outcome,
  fingerprint,
  signature,
  meta,
  onVerify,
  verifyHref,
  verifyLabel = 'Verify decision',
  className,
}: DecisionReceiptProps) {
  return (
    <article className={cx('ip-receipt', className)}>
      <header className="ip-receipt-head">
        <div className="ip-receipt-brand">
          <Wordmark height={28} />
          <span className="ip-receipt-kicker">/ decision receipt</span>
        </div>
        <span className="ip-mono-data">{id ?? '[decision ID]'}</span>
      </header>
      <div className="ip-receipt-q">
        <span className="ip-label">Question</span>
        <p className="ip-receipt-question">{question}</p>
      </div>
      <div className="ip-receipt-grid">
        <div className="ip-receipt-col">
          <span className="ip-label">Premises</span>
          <ul className="ip-premises">
            {premises.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
        <div className="ip-receipt-col">
          <span className="ip-label">Conclusion</span>
          <Status tone={status} />
          {outcome ? <p className="ip-receipt-outcome">{outcome}</p> : null}
        </div>
      </div>
      <footer className="ip-receipt-foot">
        <div className="ip-receipt-meta">
          <span className="ip-mono-data">
            fingerprint {fingerprint ?? '[hash]'} · signature {signature ?? '[key]'}
          </span>
          <span className="ip-muted-text">{meta ?? '[agent] · [date and time]'}</span>
        </div>
        {verifyHref ? (
          <Button variant="primary" size="sm" href={verifyHref}>
            {verifyLabel}
          </Button>
        ) : onVerify ? (
          <Button variant="primary" size="sm" onClick={onVerify}>
            {verifyLabel}
          </Button>
        ) : null}
      </footer>
    </article>
  );
}
