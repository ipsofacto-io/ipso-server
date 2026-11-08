// The decision an approval writes (ADR-0110). The registry keeps the front matter of an EDR as the body of a
// decision version (ADR-0085), and the server checks only the slug, the title and the premises (ADR-0109). The
// app builds all sixteen keys of EDR draft 0.2 so that what a person approves reads the same in the registry,
// in a verdict, and in the MCP tools. A verdict names a decision by its EDR id.
import type { ApprovalRequest, Scope } from '../api/types';
import type { Json } from '../lib/json';
import { newUlid } from '../lib/ulid';
import { safeHttpsUrl } from '../lib/url';

export const CRITICALITIES = ['blocking', 'warning', 'advisory'] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export const SLUG_MAX = 128;
export const TITLE_MAX = 300;
export const SCOPES_MAX = 100;

const SLUG = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const OWNER = /^team:[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const HTTPS_URL = /^https:\/\/\S+$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** A lowercase slug from a title: words joined by hyphens, with no accent, at most 128 characters. */
export function slugFrom(title: string): string {
  const words = title
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return words.slice(0, SLUG_MAX).replace(/-+$/g, '');
}

/** Whether a string is a real calendar date in the form 2026-11-08. */
export function isDate(value: string): boolean {
  if (!DATE.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().startsWith(value);
}

/** Today in UTC as a date. */
export function today(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

/** The date a year after `date`, which is when a decision is reviewed unless the person says otherwise. */
export function aYearAfter(date: string): string {
  if (!isDate(date)) return '';
  const [year = 0, month = 1, day = 1] = date.split('-').map(Number);
  return new Date(Date.UTC(year + 1, month - 1, day)).toISOString().slice(0, 10);
}

export interface ApprovalForm {
  title: string;
  slug: string;
  owner: string;
  criticality: Criticality;
  /** The date the decision starts, in UTC. */
  validFrom: string;
  reviewBy: string;
  /** Where the decision comes from. The EDR schema needs one https source. */
  sourceUrl: string;
  sourceType: 'pr' | 'note';
}

export type ApprovalErrors = Partial<Record<'title' | 'slug' | 'owner' | 'validFrom' | 'reviewBy' | 'sourceUrl' | 'scopes', string>>;

/** What the server and the EDR schema would refuse, said before the request, field by field. */
export function checkApproval(form: ApprovalForm, picked: readonly string[]): ApprovalErrors {
  const errors: ApprovalErrors = {};
  const title = [...form.title].length;
  if (title < 1 || title > TITLE_MAX || form.title.trim() !== form.title) {
    errors.title = `A title is 1 to ${TITLE_MAX} characters with no space at either end.`;
  }
  if (!SLUG.test(form.slug) || form.slug.length > SLUG_MAX) {
    errors.slug = 'A slug is lowercase words joined by hyphens, up to 128 characters.';
  }
  if (!OWNER.test(form.owner)) errors.owner = 'An owner is a team, written team:name in lowercase.';
  if (!isDate(form.validFrom)) errors.validFrom = 'Use a date such as 2026-11-08.';
  if (!isDate(form.reviewBy)) errors.reviewBy = 'Use a date such as 2027-11-08.';
  else if (isDate(form.validFrom) && form.reviewBy <= form.validFrom) errors.reviewBy = 'The review comes after the decision starts.';
  // A link with a user name or a password in it would be stored in the decision and shown to every reader.
  if (!HTTPS_URL.test(form.sourceUrl) || safeHttpsUrl(form.sourceUrl) === null) errors.sourceUrl = 'A source is an https link with no user name or password.';
  if (picked.length < 1) errors.scopes = 'Pick at least one scope.';
  else if (picked.length > SCOPES_MAX) errors.scopes = `Pick at most ${SCOPES_MAX} scopes.`;
  return errors;
}

type ScopeItem = { org?: string; repo?: string; paths?: string[]; env?: string[] };

/**
 * The scope of the EDR for the scopes a person picked. Each picked node becomes one item that names the org, repo,
 * path and env on its way up the tree. A domain or a service has no key in the EDR, so it adds nothing of its own.
 * A node that leaves the item empty is dropped: the registry still holds it in `scope_refs`.
 */
export function edrScope(picked: readonly string[], all: readonly Scope[]): ScopeItem[] {
  const byId = new Map(all.map((scope) => [scope.id, scope]));
  const items = new Map<string, ScopeItem>();
  for (const id of picked) {
    const item: ScopeItem = {};
    const seen = new Set<string>();
    for (let node = byId.get(id); node && !seen.has(node.id); node = node.parent_id ? byId.get(node.parent_id) : undefined) {
      seen.add(node.id);
      if (node.kind === 'org' && item.org === undefined) item.org = node.selector;
      if (node.kind === 'repo' && item.repo === undefined) item.repo = node.selector;
      if (node.kind === 'path' && item.paths === undefined) item.paths = [node.selector];
      if (node.kind === 'env' && item.env === undefined) item.env = [node.selector];
    }
    if (Object.keys(item).length > 0) items.set(JSON.stringify(item), item);
  }
  return [...items.values()];
}

/** The approval of a draft: the decision a person wrote, as the control plane takes it (ADR-0109). */
export function approvalRequest(form: ApprovalForm, picked: readonly string[], all: readonly Scope[], id: string = newUlid()): ApprovalRequest {
  const body: Json = {
    edr: 1,
    id,
    slug: form.slug,
    title: form.title,
    status: 'accepted',
    owner: form.owner,
    scope: edrScope(picked, all),
    valid_from: form.validFrom,
    valid_to: null,
    review_by: form.reviewBy,
    supersedes: [],
    criticality: form.criticality,
    checks: [],
    waivers: [],
    sources: [{ type: form.sourceType, url: form.sourceUrl }],
    tags: [],
  };
  return { outcome: 'approved', decision: { body, scope_refs: [...picked], valid_from: `${form.validFrom}T00:00:00Z` } };
}

/** A rejection carries no decision, and only a person with a role over the whole tenant may send it (ADR-0109). */
export const rejection: ApprovalRequest = { outcome: 'rejected' };

