// What the invitations screen says before it asks and after the server answers (ADR-0127). The server stays the
// authority on the name: the principal check of the database refuses it with a 400, so the only rules here are the
// ones a person can read at once. The role is one of the six a person may hold, and an agent is never invited.
import type { InvitationRole } from '../api/types';

/** The roles an invitation may give, as the API lists them. There is no `agent`: an agent is not invited. */
export const INVITATION_ROLES: readonly InvitationRole[] = ['viewer', 'contributor', 'decision-owner', 'approver', 'admin', 'auditor'];

/** The longest name of a principal, in characters. */
export const NAME_MAX = 200;

export type NameCheck = { ok: true; name: string } | { ok: false; error: string };

/** A name is 1 to 200 characters with no control character. A space at either end is dropped, as the server wants it gone. */
export function checkName(value: string): NameCheck {
  const name = value.trim();
  if (name === '') return { ok: false, error: 'Give the name of the person you are inviting.' };
  if ([...name].length > NAME_MAX) return { ok: false, error: `A name is at most ${NAME_MAX} characters.` };
  if (/\p{Cc}/u.test(name)) return { ok: false, error: 'A name has no control character, such as a tab or a line break.' };
  return { ok: true, name };
}

/** What a 409 on create means. The server answers it for two causes and does not say which. */
export const CREATE_CONFLICT =
  'Browser sign-in is not set up on this server, so nobody could use the link, or the tenant already holds 1000 open invitations. Revoke one that is no longer needed, or ask whoever runs ipso to set up sign-in.';

/** What a 400 on create means. */
export const CREATE_INVALID = 'The server refused the name or the role. Check the name and pick one of the roles in the list.';

/** The word for the role of an invitation, as the person sees it: "decision owner". */
export const roleLabel = (role: string): string => role.replace(/-/g, ' ');
