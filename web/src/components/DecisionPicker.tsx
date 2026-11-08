import { calls } from '../api/calls';
import type { Decision } from '../api/types';
import { shortId } from '../lib/format';
import { asString } from '../lib/json';
import { SelectField } from './SelectField';

const PAGE = 100;
// A tenant holds a few hundred decisions. The cap keeps a bad answer from looping the page forever.
const MAX_PAGES = 20;

/** Reads every decision in force now, a page at a time (ADR-0090). */
export async function loadAllDecisions(signal: AbortSignal): Promise<Decision[]> {
  const all = new Map<string, Decision>();
  let before: string | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const { decisions } = await calls.listDecisions({ limit: PAGE, before }, signal);
    for (const decision of decisions) all.set(decision.id, decision);
    const last = decisions.at(-1);
    if (decisions.length < PAGE || !last) break;
    before = last.id;
  }
  return [...all.values()];
}

function labelOf(decision: Decision): string {
  const title = asString(decision.body.title);
  const slug = asString(decision.body.slug);
  if (title && slug) return `${title} (${slug})`;
  return title ?? slug ?? shortId(decision.id);
}

/** A select over the decisions in force. A value that is not in the list, such as one from the address, stays as an option. */
export function DecisionPicker({
  label,
  hint,
  decisions,
  value,
  onChange,
  error,
  disabled,
}: {
  label: string;
  hint?: string;
  decisions: readonly Decision[];
  value: string;
  onChange(next: string): void;
  error?: string;
  disabled?: boolean;
}) {
  const sorted = [...decisions].sort((a, b) => labelOf(a).localeCompare(labelOf(b)));
  const known = value === '' || sorted.some((decision) => decision.id === value);
  return (
    <SelectField label={label} hint={hint} error={error} value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled}>
      <option value="">Pick a decision</option>
      {known ? null : <option value={value}>{`Decision ${shortId(value)}`}</option>}
      {sorted.map((decision) => (
        <option key={decision.id} value={decision.id}>
          {labelOf(decision)}
        </option>
      ))}
    </SelectField>
  );
}
