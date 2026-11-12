// What the export screen says before it asks (ADR-0115). The server stays the authority on the key: it reads
// one native or hybrid age public key and answers 400 for anything else, so the only rules here are the ones
// that stop a secret leaving the browser or an empty request.
import type { Export } from '../api/types';

/** A private key of age, native or post-quantum, starts with this. */
export const PRIVATE_KEY_PREFIX = 'AGE-SECRET-KEY-';

export type RecipientCheck =
  | { ok: true; recipient: string }
  | { ok: false; error: string; privateKey: boolean };

export function checkRecipient(value: string): RecipientCheck {
  const recipient = value.trim();
  if (recipient.toUpperCase().startsWith(PRIVATE_KEY_PREFIX)) {
    return { ok: false, privateKey: true, error: 'That is a private key. Never paste it here: paste the public key, which starts with age1.' };
  }
  if (recipient === '') return { ok: false, privateKey: false, error: 'Paste the age public key the archive is encrypted to.' };
  return { ok: true, recipient };
}

/** True when a read of the export was not refused: only a 401 or a 403 hides the menu entry, a busy server does not. */
export const exportNotRefused = (status: number): boolean => status !== 401 && status !== 403;

/** An export that is pending or running is being made, and a request while it is would be a 409. */
export function isUnderWay(held: Export | null): boolean {
  return held !== null && (held.state === 'pending' || held.state === 'running');
}

/** The download is offered only for a ready export that has not expired. */
export function canDownload(held: Export, now: number): boolean {
  return held.state === 'ready' && Date.parse(held.expires_at) > now;
}
