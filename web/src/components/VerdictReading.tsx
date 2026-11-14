import type { StoredVerdict } from '../api/types';
import { formatTime } from '../lib/format';

/**
 * The result of one verdict. A recorded waiver that covers it is the first reading, then the recorded baseline for a
 * run that sent the digests of its violations, then a waiver reading of no cover, and the run's own result last
 * (ADR-0122, ADR-0123). What the run reported stays next to the reading when the two differ, so a local file that
 * disagrees with the registry is seen. The decision page and audit question Q3 read a verdict the same way
 * (ADR-0124).
 */
export function VerdictReading({ verdict }: { verdict: StoredVerdict }) {
  const { baseline, waiver } = verdict;
  const covered = waiver !== null && waiver.result === 'waived';
  const shown = covered ? 'waived' : baseline ? baseline.result : waiver ? waiver.result : verdict.result;
  const agrees = shown === verdict.result || (shown === 'waived(baseline)' && verdict.result === 'waived');
  const notes: string[] = [];
  if (covered && waiver.expires_at) notes.push(`covered by a recorded waiver until ${formatTime(waiver.expires_at)}`);
  if (baseline) notes.push(`${baseline.waived} of ${baseline.fingerprints} in the recorded baseline`);
  if (!agrees) notes.push(`the run reported ${verdict.result}`);
  return (
    <>
      <span className={shown === 'fail' || shown === 'error' ? 'result result-bad' : 'result'}>{shown}</span>
      {notes.length > 0 ? <div className="muted">{notes.join(', ')}</div> : null}
    </>
  );
}
