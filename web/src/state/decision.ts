import type { Decision } from '../api/types';
import { asNumber, asRecords, asString, asStrings } from '../lib/json';
import { shortId } from '../lib/format';

/** What the views show of a decision, read from the body with no trust in its shape. */
export interface DecisionSummary {
  id: string;
  version: number;
  slug: string | null;
  /** The id of the EDR (a ULID), which a verdict names the decision by. */
  edrId: string | null;
  title: string;
  status: unknown;
  owner: string | null;
  criticality: string | null;
  validFrom: string | null;
  validTo: string | null;
  reviewBy: string | null;
  tags: string[];
}

export function summarize(decision: Decision): DecisionSummary {
  const body = decision.body;
  const slug = asString(body.slug);
  return {
    id: decision.id,
    version: decision.version,
    slug,
    edrId: asString(body.id),
    title: asString(body.title) ?? slug ?? shortId(decision.id),
    status: body.status,
    owner: asString(body.owner),
    criticality: asString(body.criticality),
    validFrom: asString(body.valid_from),
    validTo: asString(body.valid_to),
    reviewBy: asString(body.review_by),
    tags: asStrings(body.tags),
  };
}

/** The scope items of a decision, one line each: "repo acme/payments, paths src/**, env prod". */
export function scopeLines(decision: Decision): string[] {
  return asRecords(decision.body.scope).map((item) => {
    const parts: string[] = [];
    const org = asString(item.org);
    const repo = asString(item.repo);
    const paths = asStrings(item.paths);
    const env = asStrings(item.env);
    if (org) parts.push(`org ${org}`);
    if (repo) parts.push(`repo ${repo}`);
    if (paths.length > 0) parts.push(`paths ${paths.join(', ')}`);
    if (env.length > 0) parts.push(`env ${env.join(', ')}`);
    return parts.join(', ');
  }).filter((line) => line !== '');
}

export interface CheckLine {
  engine: string;
  target: string | null;
  mode: string | null;
}

export function checkLines(decision: Decision): CheckLine[] {
  return asRecords(decision.body.checks).flatMap((check) => {
    const engine = asString(check.engine);
    if (engine === null) return [];
    return [{ engine, target: asString(check.ref) ?? asString(check.target) ?? asString(check.job), mode: asString(check.mode) }];
  });
}

export interface PremiseLine {
  id: string;
  statement: string;
  every: number | null;
}

export function premiseLines(decision: Decision): PremiseLine[] {
  return asRecords(decision.body.premises).flatMap((premise) => {
    const id = asString(premise.id);
    const statement = asString(premise.statement);
    return id && statement ? [{ id, statement, every: asNumber(premise.every) }] : [];
  });
}

export interface SourceLine {
  type: string;
  url: string;
}

export function sourceLines(decision: Decision): SourceLine[] {
  return asRecords(decision.body.sources).flatMap((source) => {
    const url = asString(source.url);
    return url ? [{ type: asString(source.type) ?? 'source', url }] : [];
  });
}

export function supersedes(decision: Decision): string[] {
  return asStrings(decision.body.supersedes);
}

/** The link to a decision, by its registry id: a slug can name more than one decision. */
export function decisionPath(id: string): string {
  return `/decisions/${encodeURIComponent(id)}`;
}
