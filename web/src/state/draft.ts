// What the inbox reads of a draft before a person approves it. A proposal is written by a model, and an agent
// proposal by an agent, so only text is read from the payload and every value is checked again before it is sent.
import type { Json } from '../lib/json';
import { asString } from '../lib/json';
import { safeHttpsUrl } from '../lib/url';
import { CRITICALITIES, SLUG_MAX, slugFrom, type Criticality } from './edr';

/** The name of a draft: its title, else its slug or its statement. */
export function proposalTitle(payload: Json): string {
  return asString(payload.title) ?? asString(payload.slug) ?? asString(payload.statement) ?? 'Untitled proposal';
}

export interface DraftDefaults {
  title: string;
  slug: string;
  criticality: Criticality;
  statement: string | null;
  rationale: string | null;
  /** The https link of the pull request, or '' when the draft has none that is safe to link. */
  sourceUrl: string;
}

/** The values the approval form starts with. The person reads and changes each of them. */
export function draftDefaults(payload: Json, sourceUrl: unknown): DraftDefaults {
  const title = asString(payload.title)?.trim() ?? '';
  const given = asString(payload.slug);
  const criticality = CRITICALITIES.find((candidate) => candidate === payload.criticality) ?? 'warning';
  return {
    title,
    slug: given && given.length <= SLUG_MAX && given === slugFrom(given) ? given : slugFrom(title),
    criticality,
    statement: asString(payload.statement),
    rationale: asString(payload.rationale),
    sourceUrl: safeHttpsUrl(sourceUrl) ?? '',
  };
}
