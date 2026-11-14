// What the server refuses in a baseline, said before the request (ADR-0121, ADR-0052, ADR-0059, ADR-0109). The server
// stays the authority: a value that passes here can still be refused, and the form shows that answer.
import type { BaselineRequest } from '../api/types';
import { UUID } from './writes';

/** The version of the file that `ipso baseline export` writes. */
export const EXPORT_VERSION = 1;
/** The export of the 100,000 digests the registry allows is about 7.2 MB, so a larger file is not one. */
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
/** The guard reads at most this much of a request (ADR-0109 decision 8), which is about 15,600 digests. */
export const MAX_BODY_BYTES = 1024 * 1024;
/** What the page says when the server answers 413, which only a smaller cap than the page's can cause. */
export const TOO_LARGE = 'This baseline does not fit in one request (1 MiB, about 15,600 fingerprints), so nothing was stored. A decision has one baseline for a repository, and it cannot be split.';

const DIGEST = /^[0-9a-f]{64}$/;
// The registry's subject grammar (ADR-0051), written out again on purpose: the server checks the same expression.
const REPO = /^[a-z0-9][a-z0-9._-]{0,62}(\/[a-z0-9._-]{1,100}){1,10}$/;
const DOT_SEGMENT = /(^|\/)\.{1,2}(\/|$)/;
const MAX_REPO = 255;
const KEYS = ['baseline_export_version', 'decision_id', 'fingerprints'];
/** A digest in the body is 64 characters, two quotes and a comma. */
const PER_DIGEST = 67;

/** What `ipso baseline export` wrote, after the page checked it. */
export interface BaselineExport {
  /** The id of the EDR file of the decision, which the local baseline file names it by. */
  decisionId: string;
  fingerprints: string[];
}

export type ExportRead = { ok: true; value: BaselineExport } | { ok: false; error: string };

/** A value from a file or a server, shown as text on one line with no control character and at most 40 characters. */
export function plain(value: string): string {
  const chars = [...value.replace(/\p{Cc}/gu, ' ')];
  return chars.length > 40 ? `${chars.slice(0, 40).join('')}...` : chars.join('');
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** A file over the cap is not read at all. */
export function checkFileSize(bytes: number): string | null {
  return bytes > MAX_FILE_BYTES ? 'The file is larger than 8 MiB, so it is not the export of ipso baseline export.' : null;
}

/** Reads the text of the chosen file as the export of `ipso baseline export` and refuses anything else. */
export function readExport(text: string): ExportRead {
  const refuse = (error: string): ExportRead => ({ ok: false, error });
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return refuse('The file is not JSON. Choose the file that ipso baseline export wrote.');
  }
  if (!isRecord(value) || Object.keys(value).length !== KEYS.length || KEYS.some((key) => !(key in value))) {
    return refuse('The file is not the export of ipso baseline export: it holds baseline_export_version, decision_id and fingerprints, and nothing else.');
  }
  if (value.baseline_export_version !== EXPORT_VERSION) return refuse(`The file has another version than ${EXPORT_VERSION}, which is the one this page reads.`);
  const { decision_id: decisionId, fingerprints } = value;
  if (typeof decisionId !== 'string' || decisionId === '') return refuse('The file names no decision.');
  if (!Array.isArray(fingerprints) || fingerprints.length === 0) return refuse('The file holds no fingerprints, so there is nothing to record.');
  const seen = new Set<string>();
  for (const digest of fingerprints) {
    if (typeof digest !== 'string' || !DIGEST.test(digest)) return refuse('A fingerprint is 64 lowercase hexadecimal characters.');
    if (seen.has(digest)) return refuse('A fingerprint appears twice.');
    seen.add(digest);
  }
  return { ok: true, value: { decisionId, fingerprints: fingerprints as string[] } };
}

/** A lowercase owner/name as the registry reads a subject, which is how the server stores the repository. */
export function checkRepo(repo: string): string | null {
  if (repo.length > MAX_REPO || !REPO.test(repo) || DOT_SEGMENT.test(repo)) return 'Write the repository as a lowercase owner/name, such as acme/payments.';
  return null;
}

/**
 * The bytes of the JSON body of a baseline of `count` digests. Every digest has passed `readExport`, so each one is
 * 64 ASCII characters, and counting is exact without writing a body of 100,000 digests on every key press.
 */
export function bodyBytes(repo: string, count: number): number {
  const empty = new TextEncoder().encode(JSON.stringify({ repo, fingerprints: [] })).length;
  return count === 0 ? empty : empty + count * PER_DIGEST - 1;
}

/** How many digests one request takes for this repository. */
export function digestsThatFit(repo: string): number {
  return Math.max(0, Math.floor((MAX_BODY_BYTES - bodyBytes(repo, 0) + 1) / PER_DIGEST));
}

export interface BaselineForm {
  decisionId: string;
  /** The EDR id of the chosen decision, or null when the decision has none or is not in the list. */
  edrId: string | null;
  repo: string;
  /** The export that was read and passed its own checks, or null while none is chosen. */
  file: BaselineExport | null;
}

export type BaselineErrors = Partial<Record<'decisionId' | 'repo' | 'file', string>>;

export function checkBaseline(form: BaselineForm): BaselineErrors {
  const errors: BaselineErrors = {};
  if (!UUID.test(form.decisionId)) errors.decisionId = 'Pick the decision.';
  else if (form.edrId === null) errors.decisionId = 'This decision is not in force or has no EDR id, so no baseline file can name it.';
  const repo = checkRepo(form.repo);
  if (repo) errors.repo = repo;
  if (form.file === null) {
    errors.file = 'Choose the file that ipso baseline export wrote.';
  } else if (form.edrId !== null && form.file.decisionId !== form.edrId) {
    errors.file = `This file is for decision ${plain(form.file.decisionId)}, not for ${plain(form.edrId)}. Export the baseline of this decision.`;
  } else if (bodyBytes(form.repo, form.file.fingerprints.length) > MAX_BODY_BYTES) {
    const fit = digestsThatFit(form.repo);
    errors.file = `This file holds ${form.file.fingerprints.length.toLocaleString('en-US')} fingerprints and one request takes at most ${fit.toLocaleString('en-US')} (1 MiB). Nothing is sent.`;
  }
  return errors;
}

export function baselineRequest(repo: string, fingerprints: readonly string[]): BaselineRequest {
  return { repo, fingerprints: [...fingerprints] };
}
